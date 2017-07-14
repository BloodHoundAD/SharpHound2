using Sharphound2.OutputObjects;
using SharpHound2;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace Sharphound2.Enumeration
{
    class GroupMemberEnumeration
    {
        readonly Utils utils;
        
        public GroupMemberEnumeration()
        {
            utils = Utils.Instance;
        }

        public void StartEnumeration()
        {
            foreach (string DomainName in utils.GetDomainList())
            {
                Stopwatch watch = Stopwatch.StartNew();
                Console.WriteLine($"Started group member enumeration for {DomainName}");

                BlockingCollection<Wrapper<GroupMember>> OutputQueue = new BlockingCollection<Wrapper<GroupMember>>();
                BlockingCollection<Wrapper<SearchResultEntry>> InputQueue = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);
                
                int t = 20;

                LimitedConcurrencyLevelTaskScheduler scheduler = new LimitedConcurrencyLevelTaskScheduler(t);
                TaskFactory factory = new TaskFactory(scheduler);
                Task[] taskhandles = new Task[t];

                //Get the sid for the domain once so we can save processing later. Also saves network by omitting objectsid from our searcher
                var dsid = new SecurityIdentifier(utils.GetDomain(DomainName).GetDirectoryEntry().Properties["objectsid"].Value as byte[], 0).ToString();

                Task writer = StartOutputWriter(factory, OutputQueue);
                for (int i = 0; i < t; i++)
                {
                    taskhandles[i] = StartDataProcessor(factory, InputQueue, OutputQueue, dsid);
                }

                SearchRequest searchRequest = 
                    utils.GetSearchRequest("(|(memberof=*)(primarygroupid=*))",
                    SearchScope.Subtree,
                    new string[] { "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid", "memberof", "serviceprincipalname" },
                    DomainName);

                int TimeoutCount = 0;
                TimeSpan timeout = new TimeSpan(0, 0, 30);
                LdapConnection connection = utils.GetLdapConnection(DomainName);

                if (searchRequest == null)
                {
                    Console.WriteLine($"Unable to contact {DomainName}");
                    continue;
                }

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
                    }catch (LdapException)
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

        Task StartOutputWriter(TaskFactory factory, BlockingCollection<Wrapper<GroupMember>> output)
        {
            return factory.StartNew(() =>
            {
                string path = "group_membership.csv";
                bool append = false || File.Exists(path);
                using (StreamWriter writer = new StreamWriter(path, append))
                {
                    if (!append)
                    {
                        writer.WriteLine("GroupName,AccountName,AccountType");
                    }
                    int localcount = 0;
                    foreach (Wrapper<GroupMember> w in output.GetConsumingEnumerable())
                    {
                        GroupMember info = w.Item;
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

        Task StartDataProcessor(TaskFactory factory, BlockingCollection<Wrapper<SearchResultEntry>> input, BlockingCollection<Wrapper<GroupMember>> output, string DomainSid)
        {
            return factory.StartNew(() =>
            {
                string[] props = { "samaccountname", "distinguishedname", "samaccounttype" };
                foreach (Wrapper<SearchResultEntry> en in input.GetConsumingEnumerable())
                {
                    SearchResultEntry entry = en.Item;
                    if (!utils.GetMap(entry.DistinguishedName, out string PrincipalDisplayName))
                    {
                        PrincipalDisplayName = entry.ResolveBloodhoundDisplay();
                    }

                    if (PrincipalDisplayName == null)
                    {
                        continue;
                    }

                    string PrincipalDomainName = Utils.ConvertDNToDomain(entry.DistinguishedName);
                    string DistinguishedName = entry.DistinguishedName;

                    string ObjectType = entry.GetObjectType();

                    if (ObjectType.Equals("group"))
                    {
                        utils.AddMap(entry.DistinguishedName, PrincipalDisplayName);
                    }

                    foreach (string dn in entry.GetPropArray("memberof"))
                    {
                        if (!utils.GetMap(dn, out string Group))
                        {
                            SearchResponse r;
                            using (LdapConnection conn = utils.GetLdapConnection(PrincipalDomainName))
                            {
                                r = (SearchResponse)conn.SendRequest(utils.GetSearchRequest("(objectClass=group)", SearchScope.Base, props, Utils.ConvertDNToDomain(dn), dn));

                                if (r.Entries.Count >= 1)
                                {
                                    SearchResultEntry e = r.Entries[0];
                                    Group = e.ResolveBloodhoundDisplay();
                                }
                                else
                                {
                                    Group = ConvertADName(dn, ADSTypes.ADS_NAME_TYPE_DN, ADSTypes.ADS_NAME_TYPE_NT4);
                                    if (Group != null)
                                    {
                                        Group = Group.Split('\\').Last();
                                    }
                                    else
                                    {
                                        Group = dn.Substring(0, dn.IndexOf(",", StringComparison.Ordinal)).Split('=').Last();
                                    }
                                }
                            }

                            if (Group != null)
                            {
                                utils.AddMap(dn, Group);
                            }
                            
                        }

                        if (Group != null)
                            output.Add(new Wrapper<GroupMember> { Item = new GroupMember() { AccountName = PrincipalDisplayName, GroupName = Group, ObjectType = ObjectType } });
                    }

                    string PrimaryGroupID = entry.GetProp("primarygroupid");
                    if (PrimaryGroupID != null)
                    {
                        string pgsid = $"{DomainSid}-{PrimaryGroupID}";
                        if (!utils.GetMap(pgsid, out string Group))
                        {
                            SearchResponse r;
                            using (LdapConnection conn = utils.GetLdapConnection(PrincipalDomainName))
                            {
                                r = (SearchResponse)conn.SendRequest(utils.GetSearchRequest($"(objectsid={pgsid})", SearchScope.Subtree, props, PrincipalDomainName));

                                if (r.Entries.Count >= 1)
                                {
                                    SearchResultEntry e = r.Entries[0];
                                    Group = e.ResolveBloodhoundDisplay();
                                    if (Group != null)
                                    {
                                        utils.AddMap(pgsid, Group);
                                    }
                                }
                            }
                        }

                        if (Group != null)
                            output.Add(new Wrapper<GroupMember> { Item = new GroupMember() { AccountName = PrincipalDisplayName, GroupName = Group, ObjectType = ObjectType } });
                    }
                    en.Item = null;
                }
            });
        }

        #region Pinvoke
        public enum ADSTypes
        {
            ADS_NAME_TYPE_DN = 1,
            ADS_NAME_TYPE_CANONICAL = 2,
            ADS_NAME_TYPE_NT4 = 3,
            ADS_NAME_TYPE_DISPLAY = 4,
            ADS_NAME_TYPE_DOMAIN_SIMPLE = 5,
            ADS_NAME_TYPE_ENTERPRISE_SIMPLE = 6,
            ADS_NAME_TYPE_GUID = 7,
            ADS_NAME_TYPE_UNKNOWN = 8,
            ADS_NAME_TYPE_USER_PRINCIPAL_NAME = 9,
            ADS_NAME_TYPE_CANONICAL_EX = 10,
            ADS_NAME_TYPE_SERVICE_PRINCIPAL_NAME = 11,
            ADS_NAME_TYPE_SID_OR_SID_HISTORY_NAME = 12
        }

        public string ConvertADName(string ObjectName, ADSTypes InputType, ADSTypes OutputType)
        {
            string Domain;

            Type TranslateName;
            object TranslateInstance;

            if (InputType.Equals(ADSTypes.ADS_NAME_TYPE_NT4))
            {
                ObjectName = ObjectName.Replace("/", "\\");
            }

            switch (InputType)
            {
                case ADSTypes.ADS_NAME_TYPE_NT4:
                    Domain = ObjectName.Split('\\')[0];
                    break;
                case ADSTypes.ADS_NAME_TYPE_DOMAIN_SIMPLE:
                    Domain = ObjectName.Split('@')[1];
                    break;
                case ADSTypes.ADS_NAME_TYPE_CANONICAL:
                    Domain = ObjectName.Split('/')[0];
                    break;
                case ADSTypes.ADS_NAME_TYPE_DN:
                    Domain = ObjectName.Substring(ObjectName.IndexOf("DC=", StringComparison.Ordinal)).Replace("DC=", "").Replace(",", ".");
                    break;
                default:
                    Domain = "";
                    break;
            }

            try
            {
                TranslateName = Type.GetTypeFromProgID("NameTranslate");
                TranslateInstance = Activator.CreateInstance(TranslateName);

                object[] args = new object[2];
                args[0] = 1;
                args[1] = Domain;
                TranslateName.InvokeMember("Init", BindingFlags.InvokeMethod, null, TranslateInstance, args);

                args = new object[2];
                args[0] = (int)InputType;
                args[1] = ObjectName;
                TranslateName.InvokeMember("Set", BindingFlags.InvokeMethod, null, TranslateInstance, args);

                args = new object[1];
                args[0] = (int)OutputType;

                string Result = (string)TranslateName.InvokeMember("Get", BindingFlags.InvokeMethod, null, TranslateInstance, args);

                return Result;
            }
            catch
            {
                return null;
            }
        }
        #endregion
    }
}
