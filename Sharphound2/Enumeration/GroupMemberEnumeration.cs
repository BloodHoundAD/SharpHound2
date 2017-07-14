using Sharphound2.OutputObjects;
using SharpHound2;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Reflection;
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


                Task writer = StartOutputWriter(factory, OutputQueue);
                for (int i = 0; i < t; i++)
                {
                    taskhandles[i] = StartDataProcessor(factory, InputQueue, OutputQueue);
                }

                SearchRequest searchRequest = 
                    utils.GetSearchRequest("(|(memberof=*)(primarygroupid=*))",
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    new string[] { "objectsid", "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid", "memberof", "serviceprincipalname" },
                    DomainName);

                LdapConnection connection = utils.GetLdapConnection(DomainName);

                if (searchRequest == null)
                {
                    Console.WriteLine($"Unable to contact {DomainName}");
                    continue;
                }

                //Add our paging control
                PageResultRequestControl prc = new PageResultRequestControl(500);
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
                        InputQueue.Add(new Wrapper<SearchResultEntry>()
                        {
                            Item = entry
                        });
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

        Task StartDataProcessor(TaskFactory factory, BlockingCollection<Wrapper<SearchResultEntry>> input, BlockingCollection<Wrapper<GroupMember>> output)
        {
            return factory.StartNew(() =>
            {
                
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

                    string ObjectType = entry.GetObjectType();

                    if (ObjectType.Equals("group"))
                    {
                        utils.AddMap(entry.DistinguishedName, PrincipalDisplayName);
                    }

                    foreach (string dn in entry.GetPropArray("memberof"))
                    {
                        if (!utils.GetMap(dn, out string Group))
                        {
                            string domainname = Utils.ConvertDNToDomain(dn);
                            SearchResponse r = utils.GetSingleSearcher("(objectClass=group)", new string[] { "samaccountname", "distinguishedname", "samaccounttype" }, out LdapConnection conn, ADSPath: dn, DomainName: domainname);
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

                            conn.Dispose();

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
                        string domainsid = entry.Sid().Substring(0, entry.Sid().LastIndexOf("-", StringComparison.Ordinal));
                        string pgsid = $"{domainsid}-{PrimaryGroupID}";
                        if (!utils.GetMap(pgsid, out string Group))
                        {
                            SearchResponse r = utils.GetSimpleSearcher($"(objectsid={pgsid})", new string[] { "samaccountname", "distinguishedname", "samaccounttype" }, out LdapConnection conn, Utils.ConvertDNToDomain(entry.DistinguishedName));
                            if (r.Entries.Count >= 1)
                            {
                                SearchResultEntry e = r.Entries[0];
                                Group = e.ResolveBloodhoundDisplay();
                                if (Group != null)
                                {
                                    utils.AddMap(pgsid, Group);
                                }
                            }
                            conn.Dispose();
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
