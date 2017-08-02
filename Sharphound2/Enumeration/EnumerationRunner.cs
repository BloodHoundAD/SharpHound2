using System;
using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Threading.Tasks;
using Sharphound2.OutputObjects;
using SharpHound2;
using static Sharphound2.Sharphound;

namespace Sharphound2.Enumeration
{
    internal class EnumerationRunner
    {
        private int _lastCount;
        private int _currentCount;
        private readonly Options _options;
        private readonly System.Timers.Timer _statusTimer;
        private readonly Utils _utils;
        private string _currentDomainSid;
        private string _currentDomain;

        public EnumerationRunner(Options opts)
        {
            _options = opts;
            _utils = Utils.Instance;
            _statusTimer = new System.Timers.Timer();
            _statusTimer.Elapsed += (sender, e) =>
            {
                PrintStatus();
            };

            _statusTimer.AutoReset = false;
            _statusTimer.Interval = _options.Interval;
        }

        private void PrintStatus()
        {
            
        }

        public void StartEnumeration()
        {
            //Let's determine what LDAP filter we need first
            string ldapFilter = null;
            string[] props = { };
            switch (_options.CollectMethod)
            {
                case CollectionMethod.Group:
                    ldapFilter = "(|(memberof=*)(primarygroupid=*))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid",
                        "memberof", "serviceprincipalname"
                    };
                    break;
                case CollectionMethod.ComputerOnly:
                    ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype"
                    };
                    break;
                case CollectionMethod.LocalGroup:
                    ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype"
                    };
                    break;
                case CollectionMethod.GPOLocalGroup:
                    ldapFilter = "(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))";
                    props = new[]
                    {
                        "displayname", "name", "gpcfilesyspath"
                    };
                    break;
                case CollectionMethod.Session:
                    ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype"
                    };
                    break;
                case CollectionMethod.LoggedOn:
                    ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype"
                    };
                    break;
                case CollectionMethod.Trusts:
                    break;
                case CollectionMethod.ACL:
                    ldapFilter =
                         "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectClass=domain))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "ntsecuritydescriptor"
                    };
                    break;
                case CollectionMethod.SessionLoop:
                    ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype"
                    };
                    break;
                case CollectionMethod.Default:
                    ldapFilter = "(|(memberof=*)(primarygroupid=*)(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "serviceprincipalname"
                    };
                    break;
            }

            foreach (var domainName in _utils.GetDomainList())
            {
                Console.WriteLine($"Starting enumeration for {domainName}");

                _currentDomain = domainName;
                _currentDomainSid = _utils.GetDomainSid(domainName);
                var outputQueue = new BlockingCollection<Wrapper<OutputBase>>();
                var inputQueue = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);

                var scheduler = new LimitedConcurrencyLevelTaskScheduler(_options.Threads);
                var factory = new TaskFactory(scheduler);
                var taskhandles = new Task[_options.Threads];

                var writer = StartOutputWriter(factory, outputQueue);
                for (var i = 0; i < _options.Threads; i++)
                {
                    taskhandles[i] = StartRunner(factory, inputQueue, outputQueue);
                }

                var searchRequest =
                    _utils.GetSearchRequest(
                        ldapFilter,
                        SearchScope.Subtree,
                        props,
                        domainName);

                if (_options.CollectMethod.Equals(CollectionMethod.ACL))
                {
                    var sdfc =
                        new SecurityDescriptorFlagControl { SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner };
                    searchRequest.Controls.Add(sdfc);
                }
                

                if (searchRequest == null)
                {
                    Console.WriteLine($"Unable to contact {domainName}");
                    continue;
                }

                var connection = _utils.GetLdapConnection(domainName);
                var prc = new PageResultRequestControl(500);
                searchRequest.Controls.Add(prc);

                while (true)
                {
                    try
                    {
                        var response = (SearchResponse)connection.SendRequest(searchRequest);

                        var pageResponse =
                            (PageResultResponseControl)response.Controls[0];

                        foreach (SearchResultEntry entry in response.Entries)
                        {
                            inputQueue.Add(new Wrapper<SearchResultEntry>()
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

                    }
                }

                connection.Dispose();
                inputQueue.CompleteAdding();
                Task.WaitAll(taskhandles);
                if (_options.CollectMethod.Equals(CollectionMethod.ACL))
                {
                    foreach (var a in AclHelpers.GetSyncers())
                    {
                        outputQueue.Add(new Wrapper<OutputBase> {Item = a});
                    }
                }
                AclHelpers.ClearSyncers();
                outputQueue.CompleteAdding();
                writer.Wait();
                Console.WriteLine($"Finished enumeration for {domainName}");
            }
        }

        public Task StartRunner(TaskFactory factory, BlockingCollection<Wrapper<SearchResultEntry>> processQueue, BlockingCollection<Wrapper<OutputBase>> writeQueue)
        {
            return factory.StartNew(() =>
            {
                foreach (var wrapper in processQueue.GetConsumingEnumerable())
                {
                    var entry = wrapper.Item;

                    var type = entry.GetObjectType();
                    var name = entry.ResolveBloodhoundDisplay();

                    switch (_options.CollectMethod)
                    {
                        case CollectionMethod.Group:
                            {
                                var groups = GroupHelpers.ProcessAdObject(entry, _currentDomainSid);
                                foreach (var g in groups)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = g });
                                }
                            }
                            break;
                        case CollectionMethod.ComputerOnly:
                            {
                                if (!_utils.PingHost(name))
                                {
                                    wrapper.Item = null;
                                    continue;
                                }

                                var sessions = SessionHelpers.GetNetSessions(name, _currentDomain);
                                foreach (var s in sessions)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = s });
                                }
                                var admins =
                                    LocalAdminHelpers.GetLocalAdmins(name, "Administrators", _currentDomain,
                                        _currentDomainSid);
                                foreach (var a in admins)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = a });
                                }
                            }
                            break;
                        case CollectionMethod.LocalGroup:
                            {
                                if (!_utils.PingHost(name))
                                {
                                    wrapper.Item = null;
                                    continue;
                                }

                                var admins =
                                    LocalAdminHelpers.GetLocalAdmins(name, "Administrators", _currentDomain,
                                        _currentDomainSid);
                                foreach (var a in admins)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = a });
                                }
                            }
                            break;
                        case CollectionMethod.GPOLocalGroup:
                            foreach (var admin in LocalAdminHelpers.GetGpoAdmins(entry, _currentDomain))
                            {
                                writeQueue.Add(new Wrapper<OutputBase> {Item = admin});
                            }
                            break;
                        case CollectionMethod.Session:
                            {
                                if (!_utils.PingHost(name))
                                {
                                    wrapper.Item = null;
                                    continue;
                                }

                                var sessions = SessionHelpers.GetNetSessions(name, _currentDomain);
                                foreach (var s in sessions)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = s });
                                }
                            }
                            break;
                        case CollectionMethod.LoggedOn:
                            {
                                if (!_utils.PingHost(name))
                                {
                                    wrapper.Item = null;
                                    continue;
                                }
                                var samAccountName = entry.GetProp("samaccountname");
                                var sessions =
                                    SessionHelpers.GetNetLoggedOn(name, samAccountName,
                                        _currentDomain);
                                sessions.AddRange(SessionHelpers.GetRegistryLoggedOn(name));

                                foreach (var s in sessions)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = s });
                                }
                            }
                            break;
                        case CollectionMethod.Trusts:
                            break;
                        case CollectionMethod.ACL:
                            {
                                var acls = AclHelpers.ProcessAdObject(entry, _currentDomain);
                                foreach (var a in acls)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase>{Item = a});
                                }
                            }
                            break;
                        case CollectionMethod.SessionLoop:
                            break;
                        case CollectionMethod.Default:
                        {
                            var groups = GroupHelpers.ProcessAdObject(entry, _currentDomainSid);
                            foreach (var g in groups)
                            {
                                writeQueue.Add(new Wrapper<OutputBase> { Item = g });
                            }

                            if (!type.Equals("computer"))
                            {
                                continue;
                            }
                            
                            if (!_utils.PingHost(name))
                            {
                                wrapper.Item = null;
                                continue;
                            }

                            var sessions = SessionHelpers.GetNetSessions(name, _currentDomain);
                            foreach (var s in sessions)
                            {
                                writeQueue.Add(new Wrapper<OutputBase> { Item = s });
                            }
                            var admins =
                                LocalAdminHelpers.GetLocalAdmins(name, "Administrators", _currentDomain,
                                    _currentDomainSid);
                            foreach (var a in admins)
                            {
                                writeQueue.Add(new Wrapper<OutputBase> { Item = a });
                            }
                        }
                        break;
                    }
                    wrapper.Item = null;
                }
            });
        }

        private static Task StartOutputWriter(TaskFactory factory, BlockingCollection<Wrapper<OutputBase>> output)
        {
            return factory.StartNew(() =>
            {
                var adminCount = 0;
                var sessionCount = 0;
                var aclCount = 0;
                var groupCount = 0;

                StreamWriter admins = null;
                StreamWriter sessions = null;
                StreamWriter acls = null;
                StreamWriter groups = null;

                foreach (var obj in output.GetConsumingEnumerable())
                {
                    var item = obj.Item;
                    if (item is GroupMember)
                    {
                        if (groups == null)
                        {
                            var exists = File.Exists("group_membership.csv");
                            groups = new StreamWriter("group_membership.csv", exists);
                            if (!exists)
                                groups.WriteLine("GroupName,AccountName,AccountType");
                        }
                        groups.WriteLine(item.ToCsv());
                        groupCount++;
                        if (groupCount % 100 == 0)
                        {
                            groups.Flush();
                        }
                    }else if (item is Session)
                    {
                        if (sessions == null)
                        {
                            var exists = File.Exists("sessions.csv");
                            sessions = new StreamWriter("sessions.csv", exists);
                            if (!exists)
                                sessions.WriteLine("UserName,ComputerName,Weight");
                        }
                        sessions.WriteLine(item.ToCsv());
                        sessionCount++;
                        if (sessionCount % 100 == 0)
                        {
                            sessions.Flush();
                        }
                    }else if (item is LocalAdmin)
                    {
                        if (admins == null)
                        {
                            var exists = File.Exists("local_admins.csv");
                            admins = new StreamWriter("local_admins.csv", exists);
                            if (!exists)
                                admins.WriteLine("ComputerName,AccountName,AccountType");
                        }
                        admins.WriteLine(item.ToCsv());
                        adminCount++;
                        if (adminCount % 100 == 0)
                        {
                            admins.Flush();
                        }
                    }else if (item is ACL)
                    {
                        if (acls == null)
                        {
                            var exists = File.Exists("acls.csv");
                            acls = new StreamWriter("acls.csv", exists);
                            if (!exists)
                                acls.WriteLine("ObjectName,ObjectType,PrincipalName,PrincipalType,ActiveDirectoryRights,ACEType,AccessControlType,IsInherited");
                        }
                        acls.WriteLine(item.ToCsv());
                        aclCount++;
                        if (aclCount % 100 == 0)
                        {
                            acls.Flush();
                        }
                    }
                }
                groups?.Dispose();
                sessions?.Dispose();
                acls?.Dispose();
                admins?.Dispose();
            });
        }
    }
}
