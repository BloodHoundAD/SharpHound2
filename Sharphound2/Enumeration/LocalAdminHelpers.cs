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
    internal class ApiFailedException : Exception {}

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

        private static byte[] _sidbytes;

        public static void Init()
        {
            _cache = Cache.Instance;
            _utils = Utils.Instance;
            var sid = new SecurityIdentifier("S-1-5-32");
            _sidbytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(_sidbytes, 0);
        }

        public static List<LocalAdmin> GetLocalAdmins(ResolvedEntry target, string group, string domainName, string domainSid)
        {
            var toReturn = new List<LocalAdmin>();
            try
            {
                toReturn = GetSamAdmins(target);
                return toReturn;
            }
            catch (SystemDownException)
            {
                return toReturn;
            }
            catch (ApiFailedException)
            {
                Utils.Verbose($"LocalGroup: Falling back to WinNT Provider for {target.BloodHoundDisplay}");
                try
                {
                    toReturn = LocalGroupWinNt(target.BloodHoundDisplay, group);
                    return toReturn;
                }
                catch
                {
                    return toReturn;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return toReturn;
            }
        }

        public static List<LocalAdmin> GetSamAdmins(ResolvedEntry entry)
        {
            //Huge thanks to Simon Mourier on StackOverflow for putting me on the right track
            //https://stackoverflow.com/questions/31464835/how-to-programatically-check-the-password-must-meet-complexity-requirements-gr/31748252

            var server = new UNICODE_STRING(entry.BloodHoundDisplay);
            var toReturn = new List<LocalAdmin>();

            //Connect to the server with the proper access maskes. This gives us our server handle

            var status = SamConnect(server, out var serverHandle,
                SamAccessMasks.SamServerLookupDomain |
                SamAccessMasks.SamServerEnumerateDomains, false);

            switch (status)
            {
                case NTSTATUS.StatusRpcServerUnavailable:
                    SamCloseHandle(serverHandle);
                    throw new SystemDownException();
                case NTSTATUS.StatusSuccess:
                    break;
                default:
                    throw new ApiFailedException();
            }

            //Use SamLookupDomainInServer with the hostname to find the machine sid if possible
            string machineSid;
            try
            {
                SamLookupDomainInSamServer(serverHandle, new UNICODE_STRING(entry.ComputerSamAccountName), out var temp);
                //This will throw an exception if we didn't actually find the alias
                machineSid = new SecurityIdentifier(temp).Value;
                SamFreeMemory(temp);
            }
            catch
            {
                machineSid = "DUMMYSTRINGSHOULDNOTMATCH";
            }

            //Open the domain for the S-1-5-32 (BUILTIN) alias
            status = SamOpenDomain(serverHandle, DomainAccessMask.Lookup | DomainAccessMask.ListAccounts, _sidbytes, out var domainHandle);
            if (!status.Equals(NTSTATUS.StatusSuccess))
            {
                SamCloseHandle(serverHandle);
                throw new ApiFailedException();
            }

            //Open the alias for Local Administrators (always RID 544)
            status = SamOpenAlias(domainHandle, AliasOpenFlags.ListMembers, 544, out var aliasHandle);
            if (!status.Equals(NTSTATUS.StatusSuccess))
            {
                SamCloseHandle(domainHandle);
                SamCloseHandle(serverHandle);
                throw new ApiFailedException();
            }

            //Get the members in the alias. This returns a list of SIDs
            status = SamGetMembersInAlias(aliasHandle, out var members, out var count);

            if (!status.Equals(NTSTATUS.StatusSuccess))
            {
                SamCloseHandle(aliasHandle);
                SamCloseHandle(domainHandle);
                SamCloseHandle(serverHandle);
                throw new ApiFailedException();
            }

            SamCloseHandle(aliasHandle);
            SamCloseHandle(domainHandle);
            SamCloseHandle(serverHandle);

            if (count == 0)
            {
                SamFreeMemory(members);
                return toReturn;
            }

            //Copy the data of our sids to a new array so it doesn't get eaten
            var grabbedSids = new IntPtr[count];
            Marshal.Copy(members, grabbedSids, 0, count);

            var sids = new string[count];

            //Convert the bytes to strings for usage
            for (var i = 0; i < count; i++)
            {
                sids[i] = new SecurityIdentifier(grabbedSids[i]).Value;
            }

            //Open the LSA policy on the target machine
            status = LsaOpenPolicy(server, default(OBJECT_ATTRIBUTES),
                LsaOpenMask.ViewLocalInfo | LsaOpenMask.LookupNames, out var policyHandle);

            if (!status.Equals(NTSTATUS.StatusSuccess))
            {
                LsaClose(policyHandle);
                SamFreeMemory(members);
                throw new ApiFailedException();
            }

            //Call LsaLookupSids using the sids we got from SamGetMembersInAlias
            status = LsaLookupSids(policyHandle, count, members, out var domainList,
                out var nameList);

            if (!status.Equals(NTSTATUS.StatusSuccess) && !status.Equals(NTSTATUS.StatusSomeMapped))
            {
                LsaClose(policyHandle);
                LsaFreeMemory(domainList);
                LsaFreeMemory(nameList);
                SamFreeMemory(members);
                throw new ApiFailedException();
            }

            //Convert the returned names into structures
            var iter = nameList;
            var translatedNames = new LSA_TRANSLATED_NAMES[count];
            for (var i = 0; i < count; i++)
            {
                translatedNames[i] = (LSA_TRANSLATED_NAMES)Marshal.PtrToStructure(iter, typeof(LSA_TRANSLATED_NAMES));
                iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(typeof(LSA_TRANSLATED_NAMES)));
            }

            //Convert the returned domain list to a structure
            var lsaDomainList =
                (LSA_REFERENCED_DOMAIN_LIST)(Marshal.PtrToStructure(domainList, typeof(LSA_REFERENCED_DOMAIN_LIST)));

            //Convert the domain list to individual structures
            var trustInfos = new LSA_TRUST_INFORMATION[lsaDomainList.count];
            iter = lsaDomainList.domains;
            for (var i = 0; i < lsaDomainList.count; i++)
            {
                trustInfos[i] = (LSA_TRUST_INFORMATION)Marshal.PtrToStructure(iter, typeof(LSA_TRUST_INFORMATION));
                iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(typeof(LSA_TRUST_INFORMATION)));
            }

            var resolvedObjects = new SamEnumerationObject[translatedNames.Length];

            //Match up sids, domain names, and account names
            for (var i = 0; i < translatedNames.Length; i++)
            {
                var x = translatedNames[i];
                resolvedObjects[i] = new SamEnumerationObject();
                
                if (x.domainIndex > trustInfos.Length || x.domainIndex > 0 || trustInfos.Length > 0)
                    continue;

                resolvedObjects[i].AccountDomain = trustInfos[x.domainIndex].name.ToString();
                resolvedObjects[i].AccountName = x.name.ToString();
                resolvedObjects[i].AccountSid = sids[i];
                resolvedObjects[i].SidUsage = x.use;
            }

            //Cleanup
            SamFreeMemory(members);
            LsaFreeMemory(domainList);
            LsaFreeMemory(nameList);
            LsaClose(policyHandle);

            //Process our list of stuff now
            foreach (var data in resolvedObjects)
            {
                var sid = data.AccountSid;
                if (sid == null)
                    continue;

                if (data.AccountName.Equals(string.Empty))
                    continue;

                if (sid.StartsWith(machineSid))
                    continue;

                string type;
                switch (data.SidUsage)
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

                if (type == null)
                    continue;

                if (data.AccountName.EndsWith("$"))
                    type = "unknown";

                string resolvedName;

                if (type.Equals("unknown"))
                {
                    var mp = _utils.UnknownSidTypeToDisplay(sid, _utils.SidToDomainName(sid),
                        AdminProps);
                    if (mp == null)
                        continue;
                    resolvedName = mp.PrincipalName;
                    type = mp.ObjectType;
                }
                else
                {
                    resolvedName = _utils.SidToDisplay(sid, _utils.SidToDomainName(sid), AdminProps, type);
                    if (resolvedName == null)
                        continue;
                }

                toReturn.Add(new LocalAdmin
                {
                    ObjectType = type,
                    ObjectName = resolvedName,
                    Server = entry.BloodHoundDisplay
                });
            }
            return toReturn;
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
                        if (!_cache.GetMapValue(sidstring, type, out var adminName))
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
                                adminName = entry.ResolveAdEntry().BloodHoundDisplay;
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

        //public static List<LocalAdmin> LocalGroupApi(string target, string group, string domainName, string domainSid)
        //{
        //    const int queryLevel = 2;
        //    var resumeHandle = IntPtr.Zero;
        //    var machineSid = "DUMMYSTRING";

        //    var LMI2 = typeof(LOCALGROUP_MEMBERS_INFO_2);
            
        //    var returnValue = NetLocalGroupGetMembers(target, group, queryLevel, out IntPtr ptrInfo, -1, out int entriesRead, out int _, resumeHandle);

        //    //Return value of 1722 indicates the system is down, so no reason to fallback to WinNT
        //    if (returnValue == 1722)
        //    {
        //        throw new SystemDownException();
        //    }

        //    //If its not 0, something went wrong, but we can fallback to WinNT provider. Throw an exception
        //    if (returnValue != 0)
        //    {
        //        throw new ApiFailedException();
        //    }

        //    var toReturn = new List<LocalAdmin>();

        //    if (entriesRead <= 0) return toReturn;

        //    var iter = ptrInfo;
        //    var list = new List<API_Encapsulator>();

        //    //Loop through the data and save them into a list for processing
        //    for (var i = 0; i < entriesRead; i++)
        //    {
        //        var data = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(iter, LMI2);
        //        ConvertSidToStringSid(data.lgrmi2_sid, out string sid);
        //        list.Add(new API_Encapsulator
        //        {
        //            Lgmi2 = data,
        //            sid = sid
        //        });
        //        iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(LMI2));
        //    }
            
        //    NetApiBufferFree(ptrInfo);
        //    //Try and determine the machine sid
            
        //    foreach (var data in list)
        //    {
        //        if (data.sid == null)
        //        {
        //            continue;
        //        }

        //        //If the sid ends with -500 and doesn't start with the DomainSID, there's a very good chance we've identified the RID500 account
        //        //Take the machine sid from there. If we don't find it, we use a dummy string
        //        if (!data.sid.EndsWith("-500", StringComparison.Ordinal) ||
        //            data.sid.StartsWith(domainSid, StringComparison.Ordinal)) continue;
        //        machineSid = new SecurityIdentifier(data.sid).AccountDomainSid.Value;
        //        break;
        //    }
            
        //    foreach (var data in list)
        //    {
        //        if (data.sid == null)
        //            continue;
        //        var objectName = data.Lgmi2.lgrmi2_domainandname;
        //        if (objectName.Split('\\').Last().Equals(""))
        //        {
        //            //Sometimes we get weird objects that are just a domain name with no user behind it.
        //            continue;
        //        }

        //        if (data.sid.StartsWith(machineSid, StringComparison.Ordinal))
        //        {
        //            //This should filter out local accounts
        //            continue;
        //        }

        //        string type;
        //        switch (data.Lgmi2.lgrmi2_sidusage)
        //        {
        //            case SID_NAME_USE.SidTypeUser:
        //                type = "user";
        //                break;
        //            case SID_NAME_USE.SidTypeGroup:
        //                type = "group";
        //                break;
        //            case SID_NAME_USE.SidTypeComputer:
        //                type = "computer";
        //                break;
        //            case SID_NAME_USE.SidTypeWellKnownGroup:
        //                type = "wellknown";
        //                break;
        //            default:
        //                type = null;
        //                break;
        //        }

        //        //I have no idea what would cause this condition
        //        if (type == null)
        //        {
        //            continue;
        //        }

        //        if (objectName.EndsWith("$", StringComparison.Ordinal))
        //        {
        //            type = "computer";
        //        }
                
        //        var resolved = _utils.SidToDisplay(data.sid, _utils.SidToDomainName(data.sid), AdminProps, type);
        //        if (resolved == null)
        //        {
        //            continue;
        //        }

        //        toReturn.Add(new LocalAdmin
        //        {
        //            ObjectName = resolved,
        //            ObjectType = type,
        //            Server = target
        //        });
        //    }
        //    return toReturn;
        //}

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

            if (!File.Exists(template))
                yield break;

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

                    var server = compEntry.ResolveAdEntry().BloodHoundDisplay;

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

        private class SamEnumerationObject
        {
            internal string AccountName { get; set; }
            internal string AccountDomain { get; set; }
            internal string AccountSid { get; set; }
            internal SID_NAME_USE SidUsage { get; set; }
        }

        #region LSA Imports
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern NTSTATUS LsaLookupSids(
            IntPtr policyHandle,
            int count,
            IntPtr enumBuffer,
            out IntPtr domainList,
            out IntPtr nameList
        );

        [DllImport("advapi32.dll")]
        private static extern NTSTATUS LsaOpenPolicy(
            UNICODE_STRING server,
            OBJECT_ATTRIBUTES objectAttributes,
            LsaOpenMask desiredAccess,
            out IntPtr policyHandle
        );

        [DllImport("advapi32.dll")]
        private static extern NTSTATUS LsaFreeMemory(
            IntPtr buffer
        );

        [DllImport("advapi32.dll")]
        private static extern NTSTATUS LsaClose(
            IntPtr buffer
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LSA_TRUST_INFORMATION
        {
            internal LSA_UNICODE_STRING name;
            private IntPtr sid;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LSA_UNICODE_STRING
        {
            private ushort length;
            private ushort maxLen;
            [MarshalAs(UnmanagedType.LPWStr)] private string name;

            public override string ToString()
            {
                return $"{name.Substring(0, length / 2)}";
            }
        }

        private struct LSA_TRANSLATED_NAMES
        {
            internal SID_NAME_USE use;
            internal LSA_UNICODE_STRING name;
            internal int domainIndex;
        }

        private struct LSA_REFERENCED_DOMAIN_LIST
        {
            public uint count;
            public IntPtr domains;
        }
        #endregion

        #region SAMR Imports

        [DllImport("samlib.dll")]
        private static extern NTSTATUS SamCloseHandle(
            IntPtr handle
        );

        [DllImport("samlib.dll")]
        private static extern NTSTATUS SamFreeMemory(
            IntPtr handle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NTSTATUS SamLookupDomainInSamServer(
            IntPtr serverHandle,
            UNICODE_STRING name,
            out IntPtr sid);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NTSTATUS SamGetMembersInAlias(
            IntPtr aliasHandle,
            out IntPtr members,
            out int count);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NTSTATUS SamOpenAlias(
            IntPtr domainHandle,
            AliasOpenFlags desiredAccess,
            int aliasId,
            out IntPtr aliasHandle
        );


        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NTSTATUS SamConnect(
            UNICODE_STRING serverName,
            out IntPtr serverHandle,
            SamAccessMasks desiredAccess,
            bool objectAttributes
            );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NTSTATUS SamEnumerateAliasesInDomain(
            IntPtr domainHandle,
            ref int enumerationContext,
            out IntPtr buffer,
            int preferredMaxLen,
            out int count
            );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NTSTATUS SamOpenAlias(
            IntPtr domainHandle,
            SamAliasFlags desiredAccess,
            int aliasId,
            out IntPtr aliasHandle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NTSTATUS SamOpenDomain(
            IntPtr serverHandle,
            DomainAccessMask desiredAccess,
            byte[] DomainSid,
            out IntPtr DomainHandle
        );

        [Flags]
        private enum AliasOpenFlags
        {
            AddMember = 0x1,
            RemoveMember = 0x2,
            ListMembers = 0x4,
            ReadInfo = 0x8,
            WriteAccount = 0x10,
            AllAccess = 0xf001f,
            Read = 0x20004,
            Write = 0x20013,
            Execute = 0x20008
        }

        [Flags]
        private enum LsaOpenMask
        {
            ViewLocalInfo = 0x1,
            ViewAuditInfo = 0x2,
            GetPrivateInfo = 0x4,
            TrustAdmin = 0x8,
            CreateAccount = 0x10,
            CreateSecret = 0x20,
            CreatePrivilege = 0x40,
            SetDefaultQuotaLimits = 0x80,
            SetAuditRequirements = 0x100,
            AuditLogAdmin = 0x200,
            ServerAdmin = 0x400,
            LookupNames = 0x800,
            Notification = 0x1000
        }

        [Flags]
        private enum DomainAccessMask
        {
            ReadPasswordParameters = 0x1,
            WritePasswordParameters = 0x2,
            ReadOtherParameters = 0x4,
            WriteOtherParameters = 0x8,
            CreateUser = 0x10,
            CreateGroup = 0x20,
            CreateAlias = 0x40,
            GetAliasMembership = 0x80,
            ListAccounts = 0x100,
            Lookup = 0x200,
            AdministerServer = 0x400,
            AllAccess = 0xf07ff,
            Read = 0x20084,
            Write = 0x2047A,
            Execute = 0x20301
        }

        [Flags]
        private enum SamAliasFlags
        {
            AddMembers = 0x1,
            RemoveMembers = 0x2,
            ListMembers = 0x4,
            ReadInfo = 0x8,
            WriteAccount = 0x10,
            AllAccess = 0xf001f,
            Read = 0x20004,
            Write = 0x20013,
            Execute = 0x20008
        }

        [Flags]
        private enum SamAccessMasks
        {
            SamServerConnect = 0x1,
            SamServerShutdown = 0x2,
            SamServerInitialize = 0x4,
            SamServerCreateDomains = 0x8,
            SamServerEnumerateDomains = 0x10,
            SamServerLookupDomain = 0x20,
            SamServerAllAccess = 0xf003f,
            SamServerRead = 0x20010,
            SamServerWrite = 0x2000e,
            SamServerExecute = 0x20021
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING : IDisposable
        {
            private readonly ushort Length;
            private readonly ushort MaximumLength;
            private IntPtr Buffer;

            public UNICODE_STRING(string s)
                : this()
            {
                if (s == null) return;
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                if (Buffer == IntPtr.Zero) return;
                Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(Buffer) : null;
            }
        }

        private struct OBJECT_ATTRIBUTES : IDisposable
        {
            public void Dispose()
            {
                if (objectName == IntPtr.Zero) return;
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }
            public int len;
            public IntPtr rootDirectory;
            public uint attribs;
            public IntPtr sid;
            public IntPtr qos;
            private IntPtr objectName;
            public UNICODE_STRING ObjectName;
        }

        private enum NTSTATUS
        {
            StatusSuccess = 0x0,
            StatusMoreEntries = 0x105,
            StatusSomeMapped = 0x107,
            StatusInvalidHandle = unchecked((int)0xC0000008),
            StatusInvalidParameter = unchecked((int)0xC000000D),
            StatusAccessDenied = unchecked((int)0xC0000022),
            StatusObjectTypeMismatch = unchecked((int)0xC0000024),
            StatusNoSuchDomain = unchecked((int)0xC00000DF),
            StatusRpcServerUnavailable = unchecked((int)0xC0020017)
        }
        #endregion

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
