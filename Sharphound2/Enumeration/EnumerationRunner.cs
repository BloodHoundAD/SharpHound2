using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Sharphound2.OutputObjects;
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
        private readonly DateTime _loopEndTime;

        private int _noPing = 0;
        private int _timeouts = 0;

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
            _statusTimer.Interval = _options.StatusInterval;

            if (!_options.CollectMethod.Equals(CollectionMethod.SessionLoop) || _options.MaxLoopTime == 0) return;
            var t = DateTime.Now;
            _loopEndTime = t.AddMinutes(_options.MaxLoopTime);
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
            var output = new BlockingCollection<Wrapper<OutputBase>>();
            var writer = StartOutputWriter(Task.Factory, output);

            foreach (var domainName in _utils.GetDomainList())
            {
                Console.WriteLine($"Starting stealth enumeration for {domainName}\n");
                var domainSid = _utils.GetDomainSid(domainName);
                switch (_options.CollectMethod)
                {
                    case CollectionMethod.Session:
                        Console.WriteLine("Doing stealth enumeration for sessions");
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
                        Console.WriteLine("Doing stealth enumeration for sessions");
                        foreach (var path in SessionHelpers.CollectStealthTargets(domainName))
                        {
                            var sessions = SessionHelpers.GetNetSessions(path, domainName);
                            foreach (var s in sessions)
                            {
                                output.Add(new Wrapper<OutputBase> { Item = s });
                            }
                        }

                        Console.WriteLine("Doing stealth enumeration for admins");
                        foreach (var entry in _utils.DoSearch(
                            "(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))", SearchScope.Subtree,
                            new[] { "displayname", "name", "gpcfilesyspath" }, domainName))
                        {
                            foreach (var admin in LocalAdminHelpers.GetGpoAdmins(entry, domainName))
                            {
                                output.Add(new Wrapper<OutputBase> { Item = admin });
                            }
                        }
                        break;
                    case CollectionMethod.Default:
                        Console.WriteLine("Doing stealth enumeration for sessions");
                        foreach (var path in SessionHelpers.CollectStealthTargets(domainName))
                        {
                            var sessions = SessionHelpers.GetNetSessions(path, domainName);
                            foreach (var s in sessions)
                            {
                                output.Add(new Wrapper<OutputBase> { Item = s });
                            }
                        }

                        Console.WriteLine("Doing stealth enumeration for admins");
                        foreach (var entry in _utils.DoSearch(
                            "(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))", SearchScope.Subtree,
                            new[] { "displayname", "name", "gpcfilesyspath" }, domainName))
                        {
                            foreach (var admin in LocalAdminHelpers.GetGpoAdmins(entry, domainName))
                            {
                                output.Add(new Wrapper<OutputBase>{Item = admin});
                            }
                        }

                        Console.WriteLine("Doing stealth enumeration for groups");
                        foreach (var entry in _utils.DoSearch("(|(memberof=*)(primarygroupid=*))",
                            SearchScope.Subtree,
                            new[]
                            {
                                "samaccountname", "distinguishedname", "dnshostname", "samaccounttype",
                                "primarygroupid", "memberof", "serviceprincipalname"
                            }, domainName))
                        {
                            var resolvedEntry = entry.ResolveAdEntry();
                            foreach (var group in GroupHelpers.ProcessAdObject(entry, resolvedEntry, domainSid))
                            {
                                output.Add(new Wrapper<OutputBase> {Item = group});
                            }
                        }
                        break;
                    case CollectionMethod.SessionLoop:
                        Console.WriteLine("Doing stealth enumeration for sessions");
                        foreach (var path in SessionHelpers.CollectStealthTargets(domainName))
                        {
                            var sessions = SessionHelpers.GetNetSessions(path, domainName);
                            foreach (var s in sessions)
                            {
                                output.Add(new Wrapper<OutputBase> { Item = s });
                            }
                        }
                        break;
                    case CollectionMethod.LoggedOn:
                        Console.WriteLine("Doing LoggedOn enumeration for stealth targets");
                        foreach (var path in SessionHelpers.CollectStealthTargets(domainName))
                        {
                            var sessions = SessionHelpers.GetNetLoggedOn(path, domainName);
                            foreach (var s in sessions)
                            {
                                output.Add(new Wrapper<OutputBase> { Item = s });
                            }
                            sessions = SessionHelpers.GetRegistryLoggedOn(path);
                            foreach (var s in sessions)
                            {
                                output.Add(new Wrapper<OutputBase> { Item = s });
                            }
                        }
                        break;
                    case CollectionMethod.Group:
                        Console.WriteLine("Doing stealth enumeration for groups");
                        foreach (var entry in _utils.DoSearch("(|(memberof=*)(primarygroupid=*))",
                            SearchScope.Subtree,
                            new[]
                            {
                                "samaccountname", "distinguishedname", "dnshostname", "samaccounttype",
                                "primarygroupid", "memberof", "serviceprincipalname"
                            }, domainName))
                        {
                            var resolvedEntry = entry.ResolveAdEntry();
                            foreach (var group in GroupHelpers.ProcessAdObject(entry, resolvedEntry, domainSid))
                            {
                                output.Add(new Wrapper<OutputBase> { Item = group });
                            }
                        }
                        break;
                    case CollectionMethod.LocalGroup:
                        //This case will never happen
                        break;
                    case CollectionMethod.GPOLocalGroup:
                        Console.WriteLine("Doing stealth enumeration for admins");
                        foreach (var entry in _utils.DoSearch(
                            "(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))", SearchScope.Subtree,
                            new[] { "displayname", "name", "gpcfilesyspath" }, domainName))
                        {
                            foreach (var admin in LocalAdminHelpers.GetGpoAdmins(entry, domainName))
                            {
                                output.Add(new Wrapper<OutputBase> { Item = admin });
                            }
                        }
                        break;
                    case CollectionMethod.Trusts:
                        var trusts = DomainTrustEnumeration.DoTrustEnumeration(domainName);
                        foreach (var trust in trusts)
                        {
                            output.Add(new Wrapper<OutputBase> {Item = trust});
                        }
                        break;
                    case CollectionMethod.ACL:
                        Console.WriteLine("Doing stealth enumeration for ACLs");
                        foreach (var entry in _utils.DoSearch(
                            "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectClass=domain))",
                            SearchScope.Subtree,
                            new[]
                            {
                                "samaccountname", "distinguishedname", "dnshostname", "samaccounttype",
                                "ntsecuritydescriptor"
                            }, domainName))
                        {
                            foreach (var acl in AclHelpers.ProcessAdObject(entry, domainName))
                            {
                                output.Add(new Wrapper<OutputBase>{Item = acl});
                            }
                        }
                        break;
                    case CollectionMethod.All:
                        Console.WriteLine("All enumeration only usable without stealth");
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
                output.CompleteAdding();
                writer.Wait();
                Console.WriteLine($"Finished stealth enumeration for {domainName}");
            }
            if (!_options.CollectMethod.Equals(CollectionMethod.SessionLoop)) return;
            if (_options.MaxLoopTime != 0)
            {
                if (DateTime.Now > _loopEndTime)
                {
                    Console.WriteLine("Exiting session loop as MaxLoopTime as passed");
                }
            }

            Console.WriteLine($"Starting next session run in {_options.LoopTime} minutes");
            new ManualResetEvent(false).WaitOne(_options.LoopTime * 60 * 1000);
            if (_options.MaxLoopTime != 0)
            {
                if (DateTime.Now > _loopEndTime)
                {
                    Console.WriteLine("Exiting session loop as MaxLoopTime as passed");
                }
            }
            Console.WriteLine("Starting next enumeration loop");
            StartStealthEnumeration();
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
                        "memberof"
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
                    if (_options.ExcludeDC)
                    {
                        ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))";
                    }
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
                    ldapFilter = "(objectclass=domain)";
                    props = new[]
                    {
                        "distinguishedname"
                    };
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
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid",
                        "memberof"
                    };
                    break;
                case CollectionMethod.All:
                    ldapFilter =
                        "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectClass=domain)(memberof=*)(primarygroupid=*))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid",
                        "memberof", "ntsecuritydescriptor"
                    };
                    break;
            }

            foreach (var domainName in _utils.GetDomainList())
            {
                Console.WriteLine($"Starting enumeration for {domainName}");

                _watch = Stopwatch.StartNew();
                _currentDomain = domainName;
                _currentDomainSid = _utils.GetDomainSid(domainName);
                _currentCount = 0;
                var outputQueue = new BlockingCollection<Wrapper<OutputBase>>();
                var inputQueue = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);

                var taskhandles = new Task[_options.Threads];

                var writer = StartOutputWriter(Task.Factory, outputQueue);

                if (_options.CollectMethod.Equals(CollectionMethod.Trusts) ||
                    _options.CollectMethod.Equals(CollectionMethod.Default) || 
                    _options.CollectMethod.Equals(CollectionMethod.All))
                {
                    foreach (var domain in DomainTrustEnumeration.DoTrustEnumeration(domainName))
                    {
                        outputQueue.Add(new Wrapper<OutputBase> { Item = domain });
                    }
                    if (_options.CollectMethod.Equals(CollectionMethod.Trusts))
                    {
                        outputQueue.CompleteAdding();
                        continue;
                    }
                }

                for (var i = 0; i < _options.Threads; i++)
                {
                    taskhandles[i] = StartRunner(Task.Factory, inputQueue, outputQueue);
                }

                _statusTimer.Start();
                
                foreach (var item in _utils.DoWrappedSearch(ldapFilter, SearchScope.Subtree, props, domainName))
                {
                    inputQueue.Add(item);
                }

                inputQueue.CompleteAdding();
                Utils.Verbose("Waiting for enumeration threads to finish");
                Task.WaitAll(taskhandles);

                _statusTimer.Stop();

                if (_options.CollectMethod.Equals(CollectionMethod.ACL))
                {
                    foreach (var a in AclHelpers.GetSyncers())
                    {
                        outputQueue.Add(new Wrapper<OutputBase> {Item = a});
                    }
                    AclHelpers.ClearSyncers();
                }
                PrintStatus();
                outputQueue.CompleteAdding();
                Utils.Verbose("Waiting for writer thread to finish");
                writer.Wait();
                _watch.Stop();
                Console.WriteLine($"Finished enumeration for {domainName} in {_watch.Elapsed}");
                Console.WriteLine($"{_noPing} hosts failed ping. {_timeouts} hosts timedout.");
                _watch = null;
            }

            if (!_options.CollectMethod.Equals(CollectionMethod.SessionLoop)) return;
            if (_options.MaxLoopTime != 0)
            {
                if (DateTime.Now > _loopEndTime)
                {
                    Console.WriteLine("Exiting session loop as MaxLoopTime as passed");
                }
            }

            Console.WriteLine($"Starting next session run in {_options.LoopTime} minutes");
            new ManualResetEvent(false).WaitOne(_options.LoopTime * 60 * 1000);
            if (_options.MaxLoopTime != 0)
            {
                if (DateTime.Now > _loopEndTime)
                {
                    Console.WriteLine("Exiting session loop as MaxLoopTime as passed");
                }
            }
            Console.WriteLine("Starting next enumeration loop");
            StartEnumeration();
        }

        public Task StartRunner(TaskFactory factory, BlockingCollection<Wrapper<SearchResultEntry>> processQueue, BlockingCollection<Wrapper<OutputBase>> writeQueue)
        {
            return factory.StartNew(() =>
            {
                foreach (var wrapper in processQueue.GetConsumingEnumerable())
                {
                    
                    var entry = wrapper.Item;

                    var resolved = entry.ResolveAdEntry();
                    
                    if (resolved == null)
                    {
                        Interlocked.Increment(ref _currentCount);
                        wrapper.Item = null;
                        continue;
                    }

                    switch (_options.CollectMethod)
                    {
                        case CollectionMethod.Group:
                            {
                                var groups = GroupHelpers.ProcessAdObject(entry, resolved, _currentDomainSid);
                                foreach (var g in groups)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = g });
                                }
                            }
                            break;
                        case CollectionMethod.ComputerOnly:
                            {
                                if (!_utils.PingHost(resolved.BloodHoundDisplay))
                                {
                                    Interlocked.Increment(ref _noPing);
                                    break;
                                }

                                try
                                {
                                    var admins = LocalAdminHelpers.GetSamAdmins(resolved);

                                    foreach (var admin in admins)
                                    {
                                        writeQueue.Add(new Wrapper<OutputBase> { Item = admin });
                                    }
                                }
                                catch (TimeoutException)
                                {
                                    Interlocked.Increment(ref _timeouts);
                                }

                                if (_options.ExcludeDC && entry.DistinguishedName.Contains("OU=Domain Controllers"))
                                {
                                    break;
                                }

                                try
                                {
                                    var sessions = SessionHelpers.GetNetSessions(resolved, _currentDomain);

                                    foreach (var session in sessions)
                                    {
                                        writeQueue.Add(new Wrapper<OutputBase> {Item = session});
                                    }
                                }
                                catch (TimeoutException)
                                {
                                    Interlocked.Increment(ref _timeouts);
                                }
                            }
                            break;
                        case CollectionMethod.LocalGroup:
                            {
                                if (!_utils.PingHost(resolved.BloodHoundDisplay))
                                {
                                    Interlocked.Increment(ref _noPing);
                                    break;
                                }

                                try
                                {
                                    var admins = LocalAdminHelpers.GetSamAdmins(resolved);

                                    foreach (var admin in admins)
                                    {
                                        writeQueue.Add(new Wrapper<OutputBase> {Item = admin});
                                    }
                                }
                                catch (TimeoutException)
                                {
                                    Interlocked.Increment(ref _timeouts);
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
                                if (!_utils.PingHost(resolved.BloodHoundDisplay))
                                {
                                    Interlocked.Increment(ref _noPing);
                                    break;
                                }

                                if (_options.ExcludeDC && entry.DistinguishedName.Contains("OU=Domain Controllers"))
                                {
                                    break;
                                }

                                try
                                {
                                    var sessions = SessionHelpers.GetNetSessions(resolved, _currentDomain);

                                    foreach (var session in sessions)
                                    {
                                        writeQueue.Add(new Wrapper<OutputBase> { Item = session });
                                    }
                                }
                                catch (TimeoutException)
                                {
                                    Interlocked.Increment(ref _timeouts);
                                }
                            }
                            break;
                        case CollectionMethod.LoggedOn:
                            {
                                if (!_utils.PingHost(resolved.BloodHoundDisplay))
                                {
                                    Interlocked.Increment(ref _noPing);
                                    break;
                                }
                                var sessions =
                                    SessionHelpers.GetNetLoggedOn(resolved,
                                        _currentDomain);

                                foreach (var s in sessions)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = s });
                                }
                                sessions = SessionHelpers.GetRegistryLoggedOn(resolved);
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
                            {
                                if (!_utils.PingHost(resolved.BloodHoundDisplay))
                                {
                                    Interlocked.Increment(ref _noPing);
                                    break;
                                }

                                if (_options.ExcludeDC && entry.DistinguishedName.Contains("OU=Domain Controllers"))
                                {
                                    break;
                                }

                                try
                                {
                                    var sessions = SessionHelpers.GetNetSessions(resolved, _currentDomain);

                                    foreach (var session in sessions)
                                    {
                                        writeQueue.Add(new Wrapper<OutputBase> { Item = session });
                                    }
                                }
                                catch (TimeoutException)
                                {
                                    Interlocked.Increment(ref _timeouts);
                                }
                            }
                            break;
                        case CollectionMethod.Default:
                            {
                                var groups = GroupHelpers.ProcessAdObject(entry, resolved, _currentDomainSid);
                                foreach (var g in groups)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = g });
                                }

                                if (!resolved.ObjectType.Equals("computer"))
                                {
                                    break;
                                }
                            
                                if (!_utils.PingHost(resolved.BloodHoundDisplay))
                                {
                                    Interlocked.Increment(ref _noPing);
                                    break;
                                }

                                try
                                {
                                    var admins = LocalAdminHelpers.GetSamAdmins(resolved);

                                    foreach (var admin in admins)
                                    {
                                        writeQueue.Add(new Wrapper<OutputBase> { Item = admin });
                                    }
                                }
                                catch (TimeoutException)
                                {
                                    Interlocked.Increment(ref _timeouts);
                                }

                                if (_options.ExcludeDC && entry.DistinguishedName.Contains("OU=Domain Controllers"))
                                {
                                    break;
                                }

                                try
                                {
                                    var sessions = SessionHelpers.GetNetSessions(resolved, _currentDomain);

                                    foreach (var session in sessions)
                                    {
                                        writeQueue.Add(new Wrapper<OutputBase> { Item = session });
                                    }
                                }
                                catch (TimeoutException)
                                {
                                    Interlocked.Increment(ref _timeouts);
                                }
                            }
                        break;
                        case CollectionMethod.All:
                            {
                                var groups = GroupHelpers.ProcessAdObject(entry, resolved, _currentDomainSid);
                                foreach (var g in groups)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = g });
                                }

                                var acls = AclHelpers.ProcessAdObject(entry, _currentDomain);
                                foreach (var a in acls)
                                {
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = a });
                                }

                                if (!resolved.ObjectType.Equals("computer"))
                                {
                                    break;
                                }

                                if (!_utils.PingHost(resolved.BloodHoundDisplay))
                                {
                                    Interlocked.Increment(ref _noPing);
                                    break;
                                }

                                try
                                {
                                    var admins = LocalAdminHelpers.GetSamAdmins(resolved);

                                    foreach (var admin in admins)
                                    {
                                        writeQueue.Add(new Wrapper<OutputBase> { Item = admin });
                                    }
                                }
                                catch (TimeoutException)
                                {
                                    Interlocked.Increment(ref _timeouts);
                                }

                                if (_options.ExcludeDC && entry.DistinguishedName.Contains("OU=Domain Controllers"))
                                {
                                    break;
                                }

                                try
                                {
                                    var sessions = SessionHelpers.GetNetSessions(resolved, _currentDomain);

                                    foreach (var session in sessions)
                                    {
                                        writeQueue.Add(new Wrapper<OutputBase> { Item = session });
                                    }
                                }
                                catch (TimeoutException)
                                {
                                    Interlocked.Increment(ref _timeouts);
                                }
                            }
                        break;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }
                    Interlocked.Increment(ref _currentCount);
                    wrapper.Item = null;
                }
            }, TaskCreationOptions.LongRunning);
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
                StreamWriter trusts = null;

                foreach (var obj in output.GetConsumingEnumerable())
                {
                    var item = obj.Item;
                    if (item is GroupMember)
                    {
                        if (groups == null)
                        {
                            var f = Utils.GetCsvFileName("group_membership.csv");
                            Utils.AddUsedFile(f);
                            var exists = File.Exists(f);
                            groups = new StreamWriter(f, exists);
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
                            var f = Utils.GetCsvFileName("sessions.csv");
                            Utils.AddUsedFile(f);
                            var exists = File.Exists(f);
                            sessions = new StreamWriter(f, exists);
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
                            var f = Utils.GetCsvFileName("local_admins.csv");
                            Utils.AddUsedFile(f);
                            var exists = File.Exists(f);
                            admins = new StreamWriter(f, exists);
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
                            var f = Utils.GetCsvFileName("acls.csv");
                            Utils.AddUsedFile(f);
                            var exists = File.Exists(f);
                            acls = new StreamWriter(f, exists);
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
                    else if (item is DomainTrust)
                    {
                        if (trusts == null)
                        {
                            var f = Utils.GetCsvFileName("trusts.csv");
                            Utils.AddUsedFile(f);
                            var exists = File.Exists(f);
                            trusts = new StreamWriter(f, exists);
                            if (!exists)
                                trusts.WriteLine("SourceDomain,TargetDomain,TrustDirection,TrustType,Transitive");
                        }
                        trusts.WriteLine(item.ToCsv());
                        trusts.Flush();
                    }
                    obj.Item = null;
                }
                groups?.Dispose();
                sessions?.Dispose();
                acls?.Dispose();
                admins?.Dispose();
                trusts?.Dispose();
            }, TaskCreationOptions.LongRunning);
        }
    }
}
