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

namespace Sharphound2.Enumeration
{
    internal static class SessionHelpers
    {
        private static Cache _cache;
        private static Utils _utils;
        private static Sharphound.Options _options;
        private static readonly string[] RegistryProps = {"samaccounttype", "samaccountname", "distinguishedname"};
        private static readonly Regex SidRegex = new Regex(@"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$", RegexOptions.Compiled);
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

        public static void Init(Sharphound.Options opts)
        {
            _cache = Cache.Instance;
            _utils = Utils.Instance;
            _options = opts;
        }

        public static IEnumerable<ResolvedEntry> CollectStealthTargets(string domainName)
        {
            //Use a dictionary to unique stuff.
            var paths = new ConcurrentDictionary<string, byte>();
            //First we want to get all user script paths/home directories/profilepaths
            Parallel.ForEach(_utils.DoSearch(
                "(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))",
                SearchScope.Subtree, new[] { "homedirectory", "scriptpath", "profilepath" },
                domainName), (x) =>
            {
                var result = x;
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
            });

            //Lets grab domain controllers as well
            if (!_options.ExcludeDC)
            {
                foreach (var entry in _utils.DoSearch("(userAccountControl:1.2.840.113556.1.4.803:=8192)",
                    SearchScope.Subtree,
                    new[] { "dnshostname", "samaccounttype", "samaccountname", "serviceprincipalname" },
                    domainName))
                {
                    var path = entry.ResolveAdEntry();
                    paths.TryAdd(path.BloodHoundDisplay, new byte());
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
                yield return new ResolvedEntry
                {
                    BloodHoundDisplay = path,
                    ObjectType = "computer",
                    ComputerSamAccountName = "FAKESTRING"
                };
            }
        }

        public static IEnumerable<Session> GetNetSessions(ResolvedEntry target, string computerDomain)
        {
            var resumeHandle = IntPtr.Zero;
            var si10 = typeof(SESSION_INFO_10);


            var entriesRead = 0;
            var ptrInfo = IntPtr.Zero;

            var t = Task<int>.Factory.StartNew(() => NetSessionEnum(target.BloodHoundDisplay, null, null, 10,
                out ptrInfo, -1, out entriesRead,
                out int _, ref resumeHandle));

            var success = t.Wait(Timeout);

            if (!success)
            {
                throw new TimeoutException();
            }

            var returnValue = t.Result;

            //If we don't get a success, just break
            if (returnValue != (int)NERR.NERR_Success) yield break;

            var results = new SESSION_INFO_10[entriesRead];
            var iter = ptrInfo;

            //Loop over the data and store it into an array
            for (var i = 0; i < entriesRead; i++)
            {
                results[i] = (SESSION_INFO_10)Marshal.PtrToStructure(iter, si10);
                iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(si10));
            }

            //Free the IntPtr
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
                    cname = target.BloodHoundDisplay;

                var dnsHostName = _utils.ResolveHost(cname);
                if (dnsHostName == null)
                    continue;

                //If we're skipping Global Catalog deconfliction, just return a session
                if (_options.SkipGcDeconfliction)
                {
                    yield return new Session { ComputerName = dnsHostName, UserName = username, Weight = 2 };
                }
                else
                {
                    //Check our cache first
                    if (!_cache.GetGcMap(username, out string[] possible) || possible == null)
                    {
                        //If we didn't get a cache hit, search the global catalog
                        var temp = new List<string>();
                        foreach (var entry in _utils.DoSearch(
                            $"(&(samAccountType=805306368)(samaccountname={username}))", SearchScope.Subtree,
                            new[] {"distinguishedname"}, null, "", true))
                        {
                            temp.Add(Utils.ConvertDnToDomain(entry.DistinguishedName).ToUpper());
                        }

                        possible = temp.ToArray();
                        _cache.AddGcMap(username, possible);
                    }

                    switch (possible.Length)
                    {
                        case 0:
                            //Object isn't in GC, so we'll default to the computer's domain
                            yield return new Session
                            {
                                UserName = $"{username}@{computerDomain}",
                                ComputerName = dnsHostName,
                                Weight = 2
                            };
                            break;
                        case 1:
                            //Exactly one instance of this samaccountname, the best scenario
                            yield return new Session
                            {
                                UserName = $"{username}@{possible.First()}",
                                ComputerName = dnsHostName,
                                Weight = 2
                            };
                            break;
                        default:
                            //Multiple possibilities (whyyyyy)
                            //Add a weight of 1 for same domain as computer, 2 for others
                            foreach (var possibility in possible)
                            {
                                var weight = possibility.Equals(computerDomain, StringComparison.CurrentCultureIgnoreCase) ? 1 : 2;

                                yield return new Session
                                {
                                    Weight = weight,
                                    ComputerName = dnsHostName,
                                    UserName = $"{username}@{possibility}"
                                };
                            }
                            break;
                    }
                }
            }
        }

        public static IEnumerable<Session> GetRegistryLoggedOn(ResolvedEntry target)
        {
            var temp = new List<Session>();
            try
            {
                //Remotely open the registry hive if its not our current one
                var key = RegistryKey.OpenRemoteBaseKey(RegistryHive.Users,
                    Environment.MachineName.Equals(target.ComputerSamAccountName, StringComparison.CurrentCultureIgnoreCase)
                        ? ""
                        : target.BloodHoundDisplay);

                //Find all the subkeys that match our regex
                var filtered = key.GetSubKeyNames()
                    .Where(sub => SidRegex.IsMatch(sub));
                
                foreach (var subkey in filtered)
                {
                    //Convert our sid to a username
                    var user = _utils.SidToDisplay(subkey, _utils.SidToDomainName(subkey),
                        RegistryProps, "user");

                    if (user == null) continue;
                    temp.Add(new Session { ComputerName = target.BloodHoundDisplay, UserName = user, Weight = 1 });
                }
            }
            catch (Exception)
            {
                yield break;
            }

            foreach (var sess in temp.Distinct())
            {
                yield return sess;
            }
        }

        public static IEnumerable<Session> GetNetLoggedOn(ResolvedEntry entry, string computerDomain)
        {
            var toReturn = new List<Session>();

            const int queryLevel = 1;
            var resumeHandle = 0;

            var tWui1 = typeof(WKSTA_USER_INFO_1);

            //Call the API to get logged on users
            var result = NetWkstaUserEnum(entry.BloodHoundDisplay, queryLevel, out IntPtr intPtr, -1, out int entriesRead, out int _, ref resumeHandle);

            //If we don't get 0 or 234 return
            if (result != 0 && result != 234) yield break;
            var iter = intPtr;
            for (var i = 0; i < entriesRead; i++)
            {
                var data = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(iter, tWui1);
                iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(tWui1));

                var domain = data.wkui1_logon_domain;
                var username = data.wkui1_username;

                if (domain.Equals(entry.ComputerSamAccountName, StringComparison.CurrentCultureIgnoreCase) ||
                    username.Trim().Equals("") || username.EndsWith("$", StringComparison.Ordinal))
                {
                    continue;
                }

                //Try to convert the domain part to a FQDN, if it doesn't work just use the computer's domain
                var domainName = _utils.DomainNetbiosToFqdn(domain) ?? computerDomain;
                toReturn.Add(new Session
                {
                    ComputerName = entry.BloodHoundDisplay,
                    UserName = $"{username}@{domainName}",
                    Weight = 1
                });
            }

            foreach (var sess in  toReturn.Distinct())
            {
                yield return sess;
            }
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
