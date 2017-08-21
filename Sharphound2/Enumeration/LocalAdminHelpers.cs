using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Sharphound2.OutputObjects;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace Sharphound2.Enumeration
{
    internal class ApiFailedException : Exception { }

    internal class SystemDownException : Exception { }

    internal static class LocalAdminHelpers
    {
        private static Cache _cache;
        private static Utils _utils;
        private static readonly Regex SectionRegex = new Regex(@"^\[(.+)\]", RegexOptions.Compiled);
        private static readonly Regex KeyRegex = new Regex(@"(.+?)\s*=(.*)", RegexOptions.Compiled);

        private static readonly string[] Props =
            {"samaccountname", "samaccounttype", "dnshostname", "serviceprincipalname", "distinguishedname"};

        private static readonly string[] GpoProps =
            {"samaccounttype", "dnshostname", "distinguishedname", "serviceprincipalname"};

        private static readonly string[] GpLinkProps = {"distinguishedname"};

        private static readonly string[] AdminProps = {"samaccountname", "dnshostname", "distinguishedname", "samaccounttype"};

        public static void Init()
        {
            _cache = Cache.Instance;
            _utils = Utils.Instance;
        }

        public static IEnumerable<LocalAdmin> GetGpoAdmins(SearchResultEntry entry, string domainName)
        {
            const string targetSid = "S-1-5-32-544__Members";

            var displayName = entry.GetProp("displayname");
            var name = entry.GetProp("name");
            var path = entry.GetProp("gpcfilesyspath");
            

            if (displayName == null || name == null || path == null)
            {
                yield break;
            }

            var template = $"{path}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf";
            var currentSection = string.Empty;
            var resolvedList = new List<MappedPrincipal>();

            using (var reader = new StreamReader(template))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    var sMatch = SectionRegex.Match(line);
                    if (sMatch.Success)
                    {
                        currentSection = sMatch.Captures[0].Value.Trim();
                    }

                    if (!currentSection.Equals("[Group Membership]"))
                    {
                        continue;
                    }

                    var kMatch = KeyRegex.Match(line);

                    if (!kMatch.Success)
                        continue;

                    var n = kMatch.Groups[1].Value;
                    var v = kMatch.Groups[2].Value;

                    if (!n.Contains(targetSid))
                        continue;

                    v = v.Trim();
                    var members = v.Split(',');


                    foreach (var m in members)
                    {
                        var member = m.Trim('*');
                        string sid;
                        if (!member.StartsWith("S-1-", StringComparison.CurrentCulture))
                        {
                            try
                            {
                                sid = new NTAccount(domainName, m).Translate(typeof(SecurityIdentifier)).Value;
                            }
                            catch
                            {
                                sid = null;
                            }
                        }
                        else
                        {
                            sid = member;
                        }

                        if (sid == null)
                            continue;

                        var domain = _utils.SidToDomainName(sid) ?? domainName;
                        var resolvedPrincipal = _utils.UnknownSidTypeToDisplay(sid, domain, Props);
                        if (resolvedPrincipal != null)
                            resolvedList.Add(resolvedPrincipal);
                    }
                }
            }

            foreach (var ouObject in _utils.DoSearch($"(gplink=*{name}*)", SearchScope.Subtree, GpLinkProps, domainName))
            {
                var adspath = ouObject.DistinguishedName;

                foreach (var compEntry in _utils.DoSearch("(objectclass=computer)", SearchScope.Subtree, GpoProps,
                    domainName, adspath))
                {
                    var samAccountType = compEntry.GetProp("samaccounttype");
                    if (samAccountType == null || samAccountType != "805306369")
                        continue;

                    var server = compEntry.ResolveBloodhoundDisplay();

                    foreach (var user in resolvedList)
                    {
                        yield return new LocalAdmin
                        {
                            ObjectName = user.PrincipalName,
                            ObjectType = user.ObjectType,
                            Server = server
                        };
                    }
                }
            }
        }

        public static IEnumerable<LocalAdmin> GetLocalAdmins(string target, string group, string domainName, string domainSid)
        {
            var toReturn = new List<LocalAdmin>();
            try
            {
                toReturn = LocalGroupApi(target, group, domainName, domainSid);
                return toReturn;
            }
            catch (SystemDownException)
            {
                return toReturn;
            }
            catch (ApiFailedException)
            {
                try
                {
                    toReturn = LocalGroupWinNt(target, group);
                    return toReturn;
                }
                catch
                {
                    return toReturn;
                }
            }
        }
        
        public static List<LocalAdmin> LocalGroupWinNt(string target, string group)
        {
            var members = new DirectoryEntry($"WinNT://{target}/{group},group");
            var localAdmins = new List<LocalAdmin>();
            try
            {
                foreach (var member in (System.Collections.IEnumerable)members.Invoke("Members"))
                {
                    using (var m = new DirectoryEntry(member))
                    {
                        //Convert sid bytes to a string
                        var sidstring = new SecurityIdentifier(m.GetSid(), 0).ToString();
                        string type;
                        switch (m.SchemaClassName)
                        {
                            case "Group":
                                type = "group";
                                break;
                            case "User":
                                //If its a user but the name ends in $, it's actually a computer (probably)
                                type = m.Properties["Name"][0].ToString().EndsWith("$", StringComparison.Ordinal) ? "computer" : "user";
                                break;
                            default:
                                type = "group";
                                break;
                        }

                        //Start by checking the cache
                        if (!_cache.GetMapValue(sidstring, type, out string adminName))
                        {
                            //Get the domain from the SID
                            var domainName = _utils.SidToDomainName(sidstring);

                            //Search for the object in AD
                            var entry = _utils
                                .DoSearch($"(objectsid={sidstring})", SearchScope.Subtree, AdminProps, domainName)
                                .DefaultIfEmpty(null).FirstOrDefault();

                            //If it's not null, we have an object, yay! Otherwise, meh
                            if (entry != null)
                            {
                                adminName = entry.ResolveBloodhoundDisplay();
                                _cache.AddMapValue(sidstring, type, adminName);
                            }
                            else
                            {
                                adminName = null;
                            }
                        }

                        if (adminName != null)
                        {
                            localAdmins.Add(new LocalAdmin { ObjectName = adminName, ObjectType = type, Server = target });
                        }
                    }
                }
            }
            catch (COMException)
            {
                //You can get a COMException, so just return a blank array
                return localAdmins;
            }

            return localAdmins;
        }

        public static List<LocalAdmin> LocalGroupApi(string target, string group, string domainName, string domainSid)
        {
            const int queryLevel = 2;
            var resumeHandle = IntPtr.Zero;
            var machineSid = "DUMMYSTRING";

            var LMI2 = typeof(LOCALGROUP_MEMBERS_INFO_2);

            var returnValue = NetLocalGroupGetMembers(target, group, queryLevel, out IntPtr ptrInfo, -1, out int entriesRead, out int _, resumeHandle);

            //Return value of 1722 indicates the system is down, so no reason to fallback to WinNT
            if (returnValue == 1722)
            {
                throw new SystemDownException();
            }

            //If its not 0, something went wrong, but we can fallback to WinNT provider. Throw an exception
            if (returnValue != 0)
            {
                throw new ApiFailedException();
            }

            var toReturn = new List<LocalAdmin>();

            if (entriesRead <= 0) return toReturn;

            var iter = ptrInfo;
            var list = new List<API_Encapsulator>();

            //Loop through the data and save them into a list for processing
            for (var i = 0; i < entriesRead; i++)
            {
                var data = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(iter, LMI2);
                ConvertSidToStringSid(data.lgrmi2_sid, out string sid);
                list.Add(new API_Encapsulator
                {
                    Lgmi2 = data,
                    sid = sid
                });
                iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(LMI2));
            }

            NetApiBufferFree(ptrInfo);

            //Try and determine the machine sid
            foreach (var data in list)
            {
                if (data.sid == null)
                {
                    continue;
                }

                //If the sid ends with -500 and doesn't start with the DomainSID, there's a very good chance we've identified the RID500 account
                //Take the machine sid from there. If we don't find it, we use a dummy string
                if (!data.sid.EndsWith("-500", StringComparison.Ordinal) ||
                    data.sid.StartsWith(domainSid, StringComparison.Ordinal)) continue;
                machineSid = new SecurityIdentifier(data.sid).AccountDomainSid.Value;
                break;
            }

            foreach (var data in list)
            {
                var objectName = data.Lgmi2.lgrmi2_domainandname;
                if (objectName.Split('\\').Last().Equals(""))
                {
                    //Sometimes we get weird objects that are just a domain name with no user behind it.
                    continue;
                }

                if (data.sid.StartsWith(machineSid, StringComparison.Ordinal))
                {
                    //This should filter out local accounts
                    continue;
                }

                string type;
                switch (data.Lgmi2.lgrmi2_sidusage)
                {
                    case SID_NAME_USE.SidTypeUser:
                        type = "user";
                        break;
                    case SID_NAME_USE.SidTypeGroup:
                        type = "group";
                        break;
                    case SID_NAME_USE.SidTypeComputer:
                        type = "computer";
                        break;
                    case SID_NAME_USE.SidTypeWellKnownGroup:
                        type = "wellknown";
                        break;
                    default:
                        type = null;
                        break;
                }

                //I have no idea what would cause this condition
                if (type == null)
                {
                    continue;
                }

                if (objectName.EndsWith("$", StringComparison.Ordinal))
                {
                    type = "computer";
                }

                var resolved = _utils.SidToDisplay(data.sid, _utils.SidToDomainName(data.sid), AdminProps, type);
                toReturn.Add(new LocalAdmin
                {
                    ObjectName = resolved,
                    ObjectType = type,
                    Server = target
                });
            }
            return toReturn;
        }

        #region pinvoke-imports
        [DllImport("NetAPI32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetLocalGroupGetMembers(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            IntPtr resume_handle);

        [DllImport("Netapi32.dll", SetLastError = true)]
        private static extern int NetApiBufferFree(IntPtr buff);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_MEMBERS_INFO_2
        {
            public IntPtr lgrmi2_sid;
            public SID_NAME_USE lgrmi2_sidusage;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lgrmi2_domainandname;
        }

        public class API_Encapsulator
        {
            public LOCALGROUP_MEMBERS_INFO_2 Lgmi2 { get; set; }
            public string sid;
        }

        public enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);
        #endregion 
    }
}
