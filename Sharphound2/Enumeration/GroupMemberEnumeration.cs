using Sharphound2.OutputObjects;
using SharpHound2;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Reflection;
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

                BlockingCollection<GroupMember> OutputQueue = new BlockingCollection<GroupMember>();
                BlockingCollection<SearchResultEntry> InputQueue = new BlockingCollection<SearchResultEntry>();


                LimitedConcurrencyLevelTaskScheduler scheduler = new LimitedConcurrencyLevelTaskScheduler(20);
                TaskFactory factory = new TaskFactory(scheduler);
                Task[] taskhandles = new Task[20];


                Task writer = StartOutputWriter(factory, OutputQueue);
                for (int i = 0; i < 20; i++)
                {
                    taskhandles[i] = StartDataProcessor(factory, InputQueue, OutputQueue);
                }

                SearchRequest searchRequest = 
                    utils.GetSearchRequest("(|(memberof=*)(primarygroupid=*))",
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    new string[] { "objectsid", "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid", "memberof" },
                    DomainName);

                LdapConnection connection = utils.GetLdapConnection(DomainName);

                if (searchRequest == null)
                {
                    Console.WriteLine($"Unable to contact {DomainName}");
                    continue;
                }

                //Add our paging control
                PageResultRequestControl prc = new PageResultRequestControl(100);
                searchRequest.Controls.Add(prc);
                int pagecount = 0;
                while (true)
                {
                    pagecount++;
                    SearchResponse response = (SearchResponse)connection.SendRequest(searchRequest);

                    PageResultResponseControl pageResponse =
                        (PageResultResponseControl)response.Controls[0];

                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        InputQueue.Add(entry);
                    }

                    if (pageResponse.Cookie.Length == 0)
                    {
                        break;
                    }

                    prc.Cookie = pageResponse.Cookie;
                }

                InputQueue.CompleteAdding();
                Task.WaitAll(taskhandles);
                OutputQueue.CompleteAdding();
                writer.Wait();
                watch.Stop();
                Console.WriteLine($"{DomainName} finished in {watch.Elapsed}");
                watch.Reset();
            }
        }

        Task StartOutputWriter(TaskFactory factory, BlockingCollection<GroupMember> output)
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
                    foreach (GroupMember info in output.GetConsumingEnumerable())
                    {
                        writer.WriteLine(info.ToCSV());
                        localcount++;
                        if (localcount % 100 == 0)
                        {
                            writer.Flush();
                        }
                    }
                    writer.Flush();
                }
            });
        }

        Task StartDataProcessor(TaskFactory factory, BlockingCollection<SearchResultEntry> input, BlockingCollection<GroupMember> output)
        {
            return factory.StartNew(() =>
            {
                foreach (SearchResultEntry entry in input.GetConsumingEnumerable())
                {
                    if (!utils.GetMap(entry.DistinguishedName, out string PrincipalDisplayName))
                    {
                        PrincipalDisplayName = entry.ResolveBloodhoundDisplay();
                    }

                    if (PrincipalDisplayName == null)
                    {
                        continue;
                    }

                    string ObjectType = entry.GetObjectType();

                    if (ObjectType.Equals("group"))
                    {
                        utils.AddMap(entry.DistinguishedName, PrincipalDisplayName);
                    }

                    foreach (string dn in entry.GetPropArray("memberof"))
                    {
                        if (!utils.GetMap(dn, out string Group))
                        {
                            SearchResponse r = utils.GetSingleSearcher("(objectClass=group)", new string[] { "samaccountname", "distinguishedname", "samaccounttype" }, ADSPath: dn, DomainName: Utils.ConvertDNToDomain(dn));
                            if (r.Entries.Count >= 1)
                            {
                                SearchResultEntry e = r.Entries[0];
                                Group = e.ResolveBloodhoundDisplay();
                                if (Group != null)
                                {
                                    utils.AddMap(dn, Group);
                                }
                            }
                        }

                        if (Group != null)
                            output.Add(new GroupMember() { AccountName = PrincipalDisplayName, GroupName = Group, ObjectType = ObjectType });
                    }

                    string PrimaryGroupID = entry.GetProp("primarygroupid");
                    if (PrimaryGroupID != null)
                    {
                        string domainsid = entry.Sid().Substring(0, entry.Sid().LastIndexOf("-", StringComparison.Ordinal));
                        string pgsid = $"{domainsid}-{PrimaryGroupID}";
                        if (!utils.GetMap(pgsid, out string Group))
                        {
                            SearchResponse r = utils.GetSimpleSearcher($"(objectsid={pgsid})", new string[] { "samaccountname", "distinguishedname", "samaccounttype" }, Utils.ConvertDNToDomain(entry.DistinguishedName));
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

                        if (Group != null)
                            output.Add(new GroupMember() { AccountName = PrincipalDisplayName, GroupName = Group, ObjectType = ObjectType });
                    }
                }
            });
        }
    }
}
