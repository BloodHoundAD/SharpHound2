using Sharphound2.OutputObjects;
using SharpHound2;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using static Sharphound2.Sharphound;

namespace Sharphound2.Enumeration
{
    class APIFailedException : Exception { }
    class SystemDownException : Exception { }

    class LocalAdminEnumeration
    {
        readonly Utils utils;
        readonly Options options;
        int LastCount;
        int CurrentCount;
        System.Timers.Timer timer;

        public LocalAdminEnumeration(Options opt)
        {
            utils = Utils.Instance;
            options = opt;
            timer = new System.Timers.Timer();
            timer.Elapsed += (sender, e) =>
            {
                //PrintStatus();
            };

            timer.AutoReset = false;
            timer.Interval = options.Interval;
        }

        public void StartEnumeration()
        {
            foreach (string DomainName in utils.GetDomainList())
            {
                Stopwatch watch = Stopwatch.StartNew();
                Console.WriteLine($"Started group member enumeration for {DomainName}");

                BlockingCollection<Wrapper<LocalAdmin>> OutputQueue = new BlockingCollection<Wrapper<LocalAdmin>>();
                BlockingCollection<Wrapper<SearchResultEntry>> InputQueue = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);

                LimitedConcurrencyLevelTaskScheduler scheduler = new LimitedConcurrencyLevelTaskScheduler(options.Threads);
                TaskFactory factory = new TaskFactory(scheduler);
                Task[] taskhandles = new Task[options.Threads];

                //Get the sid for the domain once so we can save processing later. Also saves network by omitting objectsid from our searcher
                var dsid = new SecurityIdentifier(utils.GetDomain(DomainName).GetDirectoryEntry().Properties["objectsid"].Value as byte[], 0).ToString();

                Task writer = StartOutputWriter(factory, OutputQueue);
                for (int i = 0; i < options.Threads; i++)
                {
                    taskhandles[i] = StartDataProcessor(factory, InputQueue, OutputQueue, DomainName, dsid);
                }

                SearchRequest searchRequest =
                    utils.GetSearchRequest("(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    new string[] { "dnshostname", "samaccounttype", "distinguishedname", "primarygroupid", "samaccountname", "objectsid" },
                    DomainName);

                if (searchRequest == null)
                {
                    Console.WriteLine($"Unable to contact {DomainName}");
                    continue;
                }

                int TimeoutCount = 0;
                TimeSpan timeout = new TimeSpan(0, 0, 30);
                LdapConnection connection = utils.GetLdapConnection(DomainName);

                LastCount = 0;
                CurrentCount = 0;

                timer.Start();

                //Add our paging control
                PageResultRequestControl prc = new PageResultRequestControl(500);
                searchRequest.Controls.Add(prc);
                while (true)
                {
                    try
                    {
                        SearchResponse response = (SearchResponse)connection.SendRequest(searchRequest);

                        PageResultResponseControl pageResponse =
                            (PageResultResponseControl)response.Controls[0];

                        foreach (SearchResultEntry entry in response.Entries)
                        {
                            InputQueue.Add(new Wrapper<SearchResultEntry>()
                            {
                                Item = entry
                            });
                        }

                        if (pageResponse.Cookie.Length == 0)
                        {
                            connection.Dispose();
                            break;
                        }

                        prc.Cookie = pageResponse.Cookie;
                    }
                    catch (LdapException)
                    {
                        //We hit a timeout. Add to a counter and add 30 seconds to the timeout
                        TimeoutCount++;
                        connection = utils.GetLdapConnection(DomainName);
                        if (TimeoutCount == 3)
                        {
                            //If we've timed out 4 times, just abort, cause something is weird.
                            Console.WriteLine("Aborting due to too many ldap timeouts");
                            break;
                        }
                        Console.WriteLine("Hit LDAP timeout, adding 30 seconds and retrying");
                        timeout.Add(new TimeSpan(0, 0, 30));
                        connection.Timeout = timeout;
                    }
                }

                connection.Dispose();
                InputQueue.CompleteAdding();
                Task.WaitAll(taskhandles);
                OutputQueue.CompleteAdding();
                writer.Wait();
                watch.Stop();
                Console.WriteLine($"{DomainName} finished in {watch.Elapsed}");
                watch.Reset();
            }
        }

        Task StartOutputWriter(TaskFactory factory, BlockingCollection<Wrapper<LocalAdmin>> output)
        {
            return factory.StartNew(() =>
            {
                string path = "local_admins.csv";
                bool append = false || File.Exists(path);
                using (StreamWriter writer = new StreamWriter(path, append))
                {
                    if (!append)
                    {
                        writer.WriteLine("ComputerName,AccountName,AccountType");
                    }
                    int localcount = 0;
                    foreach (Wrapper<LocalAdmin> w in output.GetConsumingEnumerable())
                    {
                        LocalAdmin info = w.Item;
                        writer.WriteLine(info.ToCSV());
                        localcount++;
                        if (localcount % 100 == 0)
                        {
                            writer.Flush();
                        }
                        w.Item = null;
                    }
                    writer.Flush();
                }
            });
        }

        Task StartDataProcessor(TaskFactory factory, BlockingCollection<Wrapper<SearchResultEntry>> input, BlockingCollection<Wrapper<LocalAdmin>> output, string DomainName, string DomainSid)
        {
            return factory.StartNew(() =>
            {
                foreach (Wrapper<SearchResultEntry> e in input.GetConsumingEnumerable())
                {
                    SearchResultEntry entry = e.Item;

                    string hostname = entry.ResolveBloodhoundDisplay();
                    if (!utils.PingHost(hostname))
                    {
                        continue;
                    }

                    List<LocalAdmin> results = new List<LocalAdmin>();
                    try
                    {
                        results = LocalGroupAPI(hostname, "Administrators", DomainName, DomainSid);
                    }
                    catch (SystemDownException)
                    {

                    }
                    catch (APIFailedException)
                    {
                        try
                        {
                            results = LocalGroupWinNT(hostname, "Administrators");
                        }
                        catch (Exception exception)
                        {
                            Console.WriteLine(exception);
                        }
                    }
                    catch (Exception exception)
                    {
                        Console.WriteLine("Exception in local admin enumeration");
                        Console.WriteLine(exception);
                        continue;
                    }
                    e.Item = null;
                    foreach (LocalAdmin la in results)
                    {
                        output.Add(new Wrapper<LocalAdmin>()
                        {
                            Item = la
                        });
                    }
                }
            });
        }

        #region Helpers
        List<LocalAdmin> LocalGroupWinNT(string Target, string group)
        {
            DirectoryEntry members = new DirectoryEntry($"WinNT://{Target}/{group},group");
            List<LocalAdmin> local_admins = new List<LocalAdmin>();
            string servername = Target.Split('.')[0].ToUpper();
            try
            {
                foreach (object member in (System.Collections.IEnumerable)members.Invoke("Members"))
                {
                    using (DirectoryEntry m = new DirectoryEntry(member))
                    {
                        string sidstring = new SecurityIdentifier(m.GetSid(), 0).ToString();
                        string type;
                        switch (m.SchemaClassName)
                        {
                            case "Group":
                                type = "group";
                                break;
                            case "User":
                                if (m.Properties["Name"][0].ToString().EndsWith("$", StringComparison.Ordinal))
                                {
                                    type = "computer";
                                }
                                else
                                {
                                    type = "user";
                                }
                                break;
                            default:
                                type = "group";
                                break;
                        }
                        
                        if (!utils.GetMap(sidstring, type, out string Admin))
                        {
                            string dsid = sidstring.Substring(0, sidstring.LastIndexOf('-'));
                            string DomainName = utils.SidToDomainName(dsid);

                            using (LdapConnection conn = utils.GetLdapConnection(DomainName))
                            {
                                SearchRequest request = utils.GetSearchRequest($"(objectsid={sidstring})",
                                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                                    new string[] { "samaccountname", "distinguishedname", "samaccounttype" },
                                    DomainName);

                                SearchResponse response = (SearchResponse)conn.SendRequest(request);

                                if (response.Entries.Count >= 1)
                                {
                                    SearchResultEntry e = response.Entries[0];
                                    Admin = e.ResolveBloodhoundDisplay();

                                    utils.AddMap(sidstring, type, Admin);
                                }
                                else
                                {
                                    Admin = null;
                                }
                            }
                        }
                        if (Admin != null)
                        {
                            local_admins.Add(new LocalAdmin() { ObjectName = Admin, ObjectType = type, Server = Target });
                        }
                    }
                }
            }
            catch (COMException)
            {
                return local_admins;
            }

            return local_admins;
        }

        List<LocalAdmin> LocalGroupAPI(string Target, string group, string DomainName, string DomainSID)
        {
            int QueryLevel = 2;
            IntPtr PtrInfo = IntPtr.Zero;
            IntPtr ResumeHandle = IntPtr.Zero;
            string MachineSID = "DUMMYSTRING";

            Type LMI2 = typeof(LOCALGROUP_MEMBERS_INFO_2);

            int ReturnValue = NetLocalGroupGetMembers(Target, group, QueryLevel, out PtrInfo, -1, out int EntriesRead, out int TotalRead, ResumeHandle);

            if (ReturnValue == 1722)
            {
                throw new SystemDownException();
            }

            if (ReturnValue != 0)
            {
                throw new APIFailedException();
            }

            List<LocalAdmin> ToReturn = new List<LocalAdmin>();

            if (EntriesRead > 0)
            {
                IntPtr iter = PtrInfo;
                List<API_Encapsulator> list = new List<API_Encapsulator>();
                for (int i = 0; i < EntriesRead; i++)
                {
                    LOCALGROUP_MEMBERS_INFO_2 data = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(iter, LMI2);
                    ConvertSidToStringSid(data.lgrmi2_sid, out string sid);
                    list.Add(new API_Encapsulator
                    {
                        Lgmi2 = data,
                        sid = sid
                    });
                    iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(LMI2));
                }

                NetApiBufferFree(PtrInfo);

                //Try and determine the machine sid
                foreach (var data in list)
                {
                    if (data.sid == null)
                    {
                        continue;
                    }

                    if (data.sid.EndsWith("-500", StringComparison.Ordinal) && !(data.sid.StartsWith(DomainSID, StringComparison.Ordinal))){
                        MachineSID = data.sid.Substring(0, data.sid.LastIndexOf("-", StringComparison.Ordinal));
                        break;
                    }
                }

                foreach (var data in list)
                {
                    string ObjectName = data.Lgmi2.lgrmi2_domainandname;
                    if (ObjectName.Split('\\').Last().Equals(""))
                    {
                        //Sometimes we get weird objects that are just a domain name with no user behind it.
                        continue;
                    }

                    if (data.sid.StartsWith(MachineSID, StringComparison.Ordinal))
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

                    if (ObjectName.EndsWith("$", StringComparison.Ordinal))
                    {
                        type = "computer";
                    }

                    string resolved = utils.SidToObject(data.sid, DomainName, new string[] { "samaccountname","samaccounttype", "distinguishedname", "dnshostname" }, type);
                    ToReturn.Add(new LocalAdmin()
                    {
                        ObjectName = resolved,
                        ObjectType = type,
                        Server = Target
                    });
                }
            }
            return ToReturn;
        }
        #endregion

        #region pinvoke-imports
        [DllImport("NetAPI32.dll", CharSet = CharSet.Unicode)]
        public extern static int NetLocalGroupGetMembers(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            IntPtr resume_handle);

        [DllImport("Netapi32.dll", SetLastError = true)]
        static extern int NetApiBufferFree(IntPtr buff);

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
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);
        #endregion 
    }
}
