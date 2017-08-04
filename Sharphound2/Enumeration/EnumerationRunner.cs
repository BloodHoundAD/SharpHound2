using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Runtime.Remoting.Messaging;
using System.Threading;
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
        private Stopwatch _watch;

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
            var l = _lastCount;
            var c = _currentCount;
            var progressStr = $"Status: {c} objects enumerated (+{c - l} {(float)c / (_watch.ElapsedMilliseconds / 1000)}/s --- Using {Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024 } MB RAM )";
            Console.WriteLine(progressStr);
            _lastCount = _currentCount;
            _statusTimer.Start();
        }

        public void StartStealthEnumeration()
        {
            var scheduler = new LimitedConcurrencyLevelTaskScheduler(_options.Threads);
            var factory = new TaskFactory(scheduler);

            var output = new BlockingCollection<Wrapper<OutputBase>>();
            var writer = StartOutputWriter(factory, output);
            //Determine what to do. Luckily a bunch of collection methods are basically identical to regular
            switch (_options.CollectMethod)
            {
                case CollectionMethod.Group:
                    StartEnumeration();
                    break;
                case CollectionMethod.ACL:
                    StartEnumeration();
                    break;
                case CollectionMethod.GPOLocalGroup:
                    StartEnumeration();
                    break;
                case CollectionMethod.Trusts:
                    StartEnumeration();
                    break;
                case CollectionMethod.ComputerOnly:
                    break;
                case CollectionMethod.LocalGroup:
                    //This shouldn't be possible, since we override it at the top level
                    break;
                case CollectionMethod.Session:
                    break;
                case CollectionMethod.LoggedOn:
                    //This doesn't make any sense
                    Console.WriteLine("LoggedOn and Stealth can't be used together!");
                    break;
                case CollectionMethod.SessionLoop:
                    break;
                case CollectionMethod.Default:
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            foreach (var domainName in _utils.GetDomainList())
            {
                Console.WriteLine($"Starting stealth enumeration for {domainName}");
                switch (_options.CollectMethod)
                {
                    case CollectionMethod.Session:
                        foreach (var path in SessionHelpers.CollectStealthTargets(domainName))
                        {
                            var sessions = SessionHelpers.GetNetSessions(path, domainName);
                            foreach (var s in sessions)
                            {
                                output.Add(new Wrapper<OutputBase>{Item = s});
                            }
                        }
                        break;
                    case CollectionMethod.ComputerOnly:
                        foreach (var path in SessionHelpers.CollectStealthTargets(domainName))
                        {
                            var sessions = SessionHelpers.GetNetSessions(path, domainName);
                            foreach (var s in sessions)
                            {
                                output.Add(new Wrapper<OutputBase> { Item = s });
                            }
                        }

                        foreach (var wrapper in _utils.DoSearch(
                            "(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))", SearchScope.Subtree,
                            new[] { "displayname", "name", "gpcfilesyspath" }, domainName))
                        {
                            foreach (var admin in LocalAdminHelpers.GetGpoAdmins(wrapper.Item, domainName))
                            {
                                output.Add(new Wrapper<OutputBase> { Item = admin });
                            }
                        }
                        break;
                    case CollectionMethod.Default:
                        Utils.Verbose("Starting session enumeration");
                        foreach (var path in SessionHelpers.CollectStealthTargets(domainName))
                        {
                            var sessions = SessionHelpers.GetNetSessions(path, domainName);
                            foreach (var s in sessions)
                            {
                                output.Add(new Wrapper<OutputBase> { Item = s });
                            }
                        }

                        Utils.Verbose("Starting gpo enumeration");
                        foreach (var wrapper in _utils.DoSearch(
                            "(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))", SearchScope.Subtree,
                            new[] { "displayname", "name", "gpcfilesyspath" }, domainName))
                        {
                            foreach (var admin in LocalAdminHelpers.GetGpoAdmins(wrapper.Item, domainName))
                            {
                                output.Add(new Wrapper<OutputBase>{Item = admin});
                            }
                        }
                        break;
                    case CollectionMethod.SessionLoop:
                        foreach (var path in SessionHelpers.CollectStealthTargets(domainName))
                        {
                            var sessions = SessionHelpers.GetNetSessions(path, domainName);
                            foreach (var s in sessions)
                            {
                                output.Add(new Wrapper<OutputBase> { Item = s });
                            }
                        }
                        break;
                }
                output.CompleteAdding();
                writer.Wait();
                Console.WriteLine($"Finished stealth enumeration for {domainName}");
            }
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
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "serviceprincipalname",
                        "memberof"
                    };
                    break;
            }

            foreach (var domainName in _utils.GetDomainList())
            {
                Console.WriteLine($"Starting enumeration for {domainName}");
                _watch = Stopwatch.StartNew();
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

                _statusTimer.Start();
                
                foreach (var item in _utils.DoSearch(ldapFilter, SearchScope.Subtree, props, domainName))
                {
                    inputQueue.Add(item);
                }

                _statusTimer.Stop();
                inputQueue.CompleteAdding();
                Task.WaitAll(taskhandles);
                if (_options.CollectMethod.Equals(CollectionMethod.ACL))
                {
                    foreach (var a in AclHelpers.GetSyncers())
                    {
                        outputQueue.Add(new Wrapper<OutputBase> {Item = a});
                    }
                }
                PrintStatus();
                AclHelpers.ClearSyncers();
                outputQueue.CompleteAdding();
                writer.Wait();
                _watch.Stop();
                Console.WriteLine($"Finished enumeration for {domainName} in {_watch.Elapsed}");
                _watch = null;
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
                    Interlocked.Increment(ref _currentCount);
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
                    obj.Item = null;
                }
                groups?.Dispose();
                sessions?.Dispose();
                acls?.Dispose();
                admins?.Dispose();
            });
        }
    }
}
