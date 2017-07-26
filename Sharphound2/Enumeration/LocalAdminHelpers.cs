using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Sharphound2.OutputObjects;

namespace Sharphound2.Enumeration
{
    internal static class LocalAdminHelpers
    {
        private static Cache _cache;
        private static Utils _utils;

        public static void Init()
        {
            _cache = Cache.Instance;
            _utils = Utils.Instance;
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
                            var dsid = sidstring.Substring(0, sidstring.LastIndexOf('-'));
                            var domainName = _utils.SidToDomainName(dsid);

                            using (var conn = _utils.GetLdapConnection(domainName))
                            {
                                var request = _utils.GetSearchRequest($"(objectsid={sidstring})",
                                    System.DirectoryServices.Protocols.SearchScope.Subtree,
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
