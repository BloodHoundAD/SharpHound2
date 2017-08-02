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
        private static readonly string[] Props = {"samaccountname", "samaccounttype", "dnshostname", "serviceprincipalname", "distinguishedname"};

        public static void Init()
        {
            _cache = Cache.Instance;
            _utils = Utils.Instance;
        }

        public static List<LocalAdmin> GetGpoAdmins(SearchResultEntry entry, string domainName)
        {
            const string targetSid = "S-1-5-32-544__Members";
            var toReturn = new List<LocalAdmin>();

            var displayName = entry.GetProp("displayname");
            var name = entry.GetProp("name");
            var path = entry.GetProp("gpcfilesyspath");

            if (displayName == null || name == null || path == null)
            {
                return toReturn;
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

            using (var conn = _utils.GetLdapConnection(domainName))
            {
                var ouSearcher =
                    _utils.GetSearchRequest($"(gplink=*{name}*)",
                        SearchScope.Subtree,
                        new[] { "distinguishedname" },
                        domainName);

                var ouResponse = (SearchResponse)conn.SendRequest(ouSearcher);
                foreach (SearchResultEntry ouObj in ouResponse.Entries)
                {
                    var adsPath = ouObj.GetProp("distinguishedname");
                    var compSearcher = _utils.GetSearchRequest("(objectclass=computer)", SearchScope.Subtree,
                        new[] { "samaccounttype", "dnshostname", "distinguishedname", "serviceprincipalname" },
                        domainName, adsPath);

                    var compResponse = (SearchResponse)conn.SendRequest(compSearcher);
                    foreach (SearchResultEntry compObj in compResponse.Entries)
                    {
                        var samAccountType = compObj.GetProp("samaccounttype");
                        if (samAccountType == null || samAccountType != "805306369")
                            continue;

                        var server = compObj.ResolveBloodhoundDisplay();

                        toReturn.AddRange(resolvedList.Select(user => new LocalAdmin
                        {
                            ObjectType = user.ObjectType,
                            ObjectName = user.PrincipalName,
                            Server = server
                        }));
                    }
                }
            }

            return toReturn;
        }

        public static List<LocalAdmin> GetLocalAdmins(string target, string group, string domainName, string domainSid)
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
                        var sidstring = new SecurityIdentifier(m.GetSid(), 0).ToString();
                        string type;
                        switch (m.SchemaClassName)
                        {
                            case "Group":
                                type = "group";
                                break;
                            case "User":
                                type = m.Properties["Name"][0].ToString().EndsWith("$", StringComparison.Ordinal) ? "computer" : "user";
                                break;
                            default:
                                type = "group";
                                break;
                        }

                        if (!_cache.GetMapValue(sidstring, type, out string adminName))
                        {
                            var domainName = _utils.SidToDomainName(sidstring);

                            using (var conn = _utils.GetLdapConnection(domainName))
                            {
                                var request = _utils.GetSearchRequest($"(objectsid={sidstring})",
                                    SearchScope.Subtree,
                                    new[] { "samaccountname", "distinguishedname", "samaccounttype" },
                                    domainName);

                                var response = (SearchResponse)conn.SendRequest(request);

                                if (response.Entries.Count >= 1)
                                {
                                    var e = response.Entries[0];
                                    adminName = e.ResolveBloodhoundDisplay();

                                    _cache.AddMapValue(sidstring, type, adminName);
                                }
                                else
                                {
                                    adminName = null;
                                }
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

            if (returnValue == 1722)
            {
                throw new SystemDownException();
            }

            if (returnValue != 0)
            {
                throw new ApiFailedException();
            }

            var toReturn = new List<LocalAdmin>();

            if (entriesRead <= 0) return toReturn;

            var iter = ptrInfo;
            var list = new List<API_Encapsulator>();
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

                if (!data.sid.EndsWith("-500", StringComparison.Ordinal) ||
                    data.sid.StartsWith(domainSid, StringComparison.Ordinal)) continue;
                machineSid = data.sid.Substring(0, data.sid.LastIndexOf("-", StringComparison.Ordinal));
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

                var resolved = _utils.SidToDisplay(data.sid, domainName, new[] { "samaccountname", "samaccounttype", "distinguishedname", "dnshostname" }, type);
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
