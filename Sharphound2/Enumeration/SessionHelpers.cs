using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;
using Sharphound2.OutputObjects;
using SearchOption = System.DirectoryServices.Protocols.SearchOption;

namespace Sharphound2.Enumeration
{
    internal static class SessionHelpers
    {
        private static Cache _cache;
        private static Utils _utils;
        private static Sharphound.Options _options;

        public static void Init(Sharphound.Options opts)
        {
            _cache = Cache.Instance;
            _utils = Utils.Instance;
            _options = opts;
        }

        public static IEnumerable<string> CollectStealthTargets(string domainName)
        {
            //Use a dictionary to unique stuff.
            var paths = new ConcurrentDictionary<string, byte>();
            //First we want to get all user script paths/home directories/profilepaths
            Parallel.ForEach(_utils.DoSearch(
                "(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))",
                SearchScope.Subtree, new[] { "homedirectory", "scriptpath", "profilepath" },
                domainName), (x) =>
            {
                var result = x.Item;
                var poss = new[]
                {
                    result.GetProp("homedirectory"), result.GetProp("scriptpath"),
                    result.GetProp("profilepath")
                };

                foreach (var s in poss)
                {
                    var split = s?.Split('\\');
                    if (!(split?.Length >= 3)) continue;
                    var path = split[2];
                    paths.TryAdd(path, new byte());
                }
                x.Item = null;
            });

            //Lets grab domain controllers as well
            if (!_options.ExcludeDC)
            {
                foreach (var entry in _utils.DoSearch("(userAccountControl:1.2.840.113556.1.4.803:=8192)",
                    SearchScope.Subtree,
                    new[] { "dnshostname", "samaccounttype", "samaccountname", "serviceprincipalname" },
                    domainName))
                {
                    var path = entry.Item.ResolveBloodhoundDisplay();
                    paths.TryAdd(path, new byte());
                }
            }

            foreach (var path in paths.Keys)
            {
                if (_options.ExcludeDC)
                {
                    if (Directory.Exists($"\\\\{path}\\SYSVOL"))
                    {
                        continue;
                    }
                }
                yield return path;
            }
        }

        public static List<Session> GetNetSessions(string target, string computerDomain)
        {
            var resumeHandle = IntPtr.Zero;
            var toReturn = new List<Session>();
            var si10 = typeof(SESSION_INFO_10);

            var returnValue = NetSessionEnum(target, null, null, 10, out IntPtr ptrInfo, -1, out int entriesRead,
                out int _, ref resumeHandle);

            if (returnValue != (int)NERR.NERR_Success) return toReturn;

            var results = new SESSION_INFO_10[entriesRead];
            var iter = ptrInfo;
            for (var i = 0; i < entriesRead; i++)
            {
                results[i] = (SESSION_INFO_10)Marshal.PtrToStructure(iter, si10);
                iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(si10));
            }

            NetApiBufferFree(ptrInfo);

            foreach (var result in results)
            {
                var username = result.sesi10_username;
                var cname = result.sesi10_cname;

                if (cname == null || username.EndsWith("$") || username.Trim() == "" || username == "$" ||
                    username == _options.CurrentUser)
                    continue;

                if (cname.StartsWith("\\", StringComparison.CurrentCulture))
                    cname = cname.TrimStart('\\');

                if (cname.Equals("[::1]") || cname.Equals("127.0.0.1"))
                    cname = target;

                var dnsHostName = _utils.ResolveHost(cname);

                if (_options.SkipGcDeconfliction)
                {
                    toReturn.Add(new Session { ComputerName = dnsHostName, UserName = username, Weight = 2 });
                }
                else
                {
                    if (!_cache.GetGcMap(username, out string[] possible))
                    {
                        using (var conn = _utils.GetGcConnection())
                        {
                            var request = new SearchRequest(null,
                                $"(&(samAccountType=805306368)(samaccountname={username}))", SearchScope.Subtree,
                                "distinguishedname");
                            var searchOptions = new SearchOptionsControl(SearchOption.DomainScope);
                            request.Controls.Add(searchOptions);
                            var response = (SearchResponse)conn.SendRequest(request);

                            var temp = new List<string>();
                            foreach (SearchResultEntry e in response.Entries)
                            {
                                var dn = e.GetProp("distinguishedname");
                                if (dn != null)
                                {
                                    temp.Add(Utils.ConvertDnToDomain(dn).ToUpper());
                                }
                            }

                            possible = temp.ToArray();
                            _cache.AddGcMap(username, possible);
                        }
                    }


                    switch (possible.Length)
                    {
                        case 0:
                            //Object isn't in GC, so we'll default to the computer's domain
                            toReturn.Add(new Session
                            {
                                UserName = $"{username}@{computerDomain}",
                                ComputerName = dnsHostName,
                                Weight = 2
                            });
                            break;
                        case 1:
                            //Exactly one instance of this samaccountname, the best scenario
                            toReturn.Add(new Session
                            {
                                UserName = $"{username}@{possible.First()}",
                                ComputerName = dnsHostName,
                                Weight = 2
                            });
                            break;
                        default:
                            //Multiple possibilities (whyyyyy)
                            //Add a weight of 1 for same domain as computer, 2 for others
                            foreach (var possibility in possible)
                            {
                                var weight = possibility.Equals(computerDomain, StringComparison.CurrentCultureIgnoreCase) ? 1 : 2;

                                toReturn.Add(new Session
                                {
                                    Weight = weight,
                                    ComputerName = dnsHostName,
                                    UserName = $"{username}@{possibility}"
                                });
                            }
                            break;
                    }
                }
            }
            return toReturn;
        }

        public static List<Session> GetRegistryLoggedOn(string target)
        {
            var toReturn = new List<Session>();
            try
            {
                var key = RegistryKey.OpenRemoteBaseKey(RegistryHive.Users,
                    Environment.MachineName.Equals(target.Split('.')[0], StringComparison.CurrentCultureIgnoreCase)
                        ? ""
                        : target);
                var filtered = key.GetSubKeyNames()
                    .Where(sub => Regex.IsMatch(sub, "S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"));

                foreach (var subkey in filtered)
                {
                    var user = _utils.SidToDisplay(subkey, _utils.SidToDomainName(subkey),
                        new[] { "samaccounttype", "samaccountname", "distinguishedname" }, "user");

                    if (user == null) continue;
                    toReturn.Add(new Session { ComputerName = target, UserName = user, Weight = 1 });
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            return toReturn.Distinct().ToList();
        }

        public static List<Session> GetNetLoggedOn(string server, string serverShortName, string computerDomain)
        {
            var toReturn = new List<Session>();

            const int queryLevel = 1;
            var resumeHandle = 0;

            var tWui1 = typeof(WKSTA_USER_INFO_1);

            var result = NetWkstaUserEnum(server, queryLevel, out IntPtr intPtr, -1, out int entriesRead, out int _, ref resumeHandle);

            if (result != 0 && result != 234) return toReturn;
            var iter = intPtr;
            for (var i = 0; i < entriesRead; i++)
            {
                var data = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(iter, tWui1);

                var domain = data.wkui1_logon_domain;
                var username = data.wkui1_username;

                if (domain.Equals(serverShortName, StringComparison.CurrentCultureIgnoreCase) ||
                    username.Trim().Equals("") || username.EndsWith("$", StringComparison.Ordinal))
                {
                    continue;
                }

                var domainName = _utils.DomainNetbiosToFqdn(domain) ?? computerDomain;
                toReturn.Add(new Session
                {
                    ComputerName = server,
                    UserName = $"{username}@{domainName}",
                    Weight = 1
                });
            }
            return toReturn.Distinct().ToList();
        }

        #region PInvoke Imports
        [DllImport("NetAPI32.dll", SetLastError = true)]
        private static extern int NetSessionEnum(
            [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            [MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
            [MarshalAs(UnmanagedType.LPWStr)] string UserName,
            int Level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref IntPtr resume_handle);

        [StructLayout(LayoutKind.Sequential)]
        public struct SESSION_INFO_10
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string sesi10_cname;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string sesi10_username;
            public uint sesi10_time;
            public uint sesi10_idle_time;
        }

        public enum NERR
        {
            NERR_Success = 0,
            ERROR_MORE_DATA = 234,
            ERROR_NO_BROWSER_SERVERS_FOUND = 6118,
            ERROR_INVALID_LEVEL = 124,
            ERROR_ACCESS_DENIED = 5,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_NOT_ENOUGH_MEMORY = 8,
            ERROR_NETWORK_BUSY = 54,
            ERROR_BAD_NETPATH = 53,
            ERROR_NO_NETWORK = 1222,
            ERROR_INVALID_HANDLE_STATE = 1609,
            ERROR_EXTENDED_ERROR = 1208,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = (NERR_BASE + 16),
            NERR_DuplicateShare = (NERR_BASE + 18),
            NERR_BufTooSmall = (NERR_BASE + 23)
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_USER_INFO_1
        {
            public string wkui1_username;
            public string wkui1_logon_domain;
            public string wkui1_oth_domains;
            public string wkui1_logon_server;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NetWkstaUserEnum(
            string servername,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(
            IntPtr Buff);
        #endregion
    }
}
