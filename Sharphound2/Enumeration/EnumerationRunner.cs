using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
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

        private int _noPing;
        private int _timeouts;

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
            var writer = _options.Uri == null
                ? StartOutputWriter(output)
                : StartRestWriter(output);

            foreach (var domainName in _utils.GetDomainList())
            {
                Console.WriteLine($"Starting stealth enumeration for {domainName}\n");
                var domainSid = _utils.GetDomainSid(domainName);
                var data = LdapFilter.GetLdapFilter(_options.CollectMethod, _options.ExcludeDC, true);
                switch (_options.CollectMethod)
                {
                    case CollectionMethod.ObjectProps:
                        Console.WriteLine("Doing stealth enumeration for object properties");
                        foreach (var entry in _utils.DoSearch(data.Filter, SearchScope.Subtree, data.Properties, domainName))
                        {
                            var resolved = entry.ResolveAdEntry();
                            OutputBase props;
                            if (resolved.ObjectType.Equals("computer"))
                            {
                                props = ObjectPropertyHelpers.GetComputerProps(entry, resolved);
                            }
                            else
                            {
                                props = ObjectPropertyHelpers.GetUserProps(entry, resolved);
                            }
                            if (props != null)
                                output.Add(new Wrapper<OutputBase> {Item = props});
                        }
                        break;
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
                            data.Filter, SearchScope.Subtree,
                            data.Properties, domainName))
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
                        foreach (var entry in _utils.DoSearch(data.Filter,
                            SearchScope.Subtree,
                            data.Properties, domainName))
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
                            data.Filter, SearchScope.Subtree,
                            data.Properties, domainName))
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
                            data.Filter,
                            SearchScope.Subtree,
                            data.Properties, domainName))
                        {
                            foreach (var acl in AclHelpers.ProcessAdObject(entry, domainName))
                            {
                                output.Add(new Wrapper<OutputBase>{Item = acl});
                            }
                        }
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
                output.CompleteAdding();
                writer.Wait();
                Console.WriteLine($"Finished stealth enumeration for {domainName}");
            }
            if (!_options.CollectMethod.Equals(CollectionMethod.SessionLoop)) return;
            if (_options.MaxLoopTime != null)
            {
                if (DateTime.Now > _options.LoopEnd)
                {
                    Console.WriteLine("Exiting session loop as LoopEndTime as passed");
                    return;
                }
            }

            Console.WriteLine($"Starting next session run in {_options.LoopTime} minutes");
            new ManualResetEvent(false).WaitOne(_options.LoopTime * 60 * 1000);
            if (_options.MaxLoopTime != null)
            {
                if (DateTime.Now > _options.LoopEnd)
                {
                    Console.WriteLine("Exiting session loop as LoopEndTime as passed");
                    return;
                }
            }
            Console.WriteLine("Starting next enumeration loop");
            StartStealthEnumeration();
        }

        public void StartEnumeration()
        {
            //Let's determine what LDAP filter we need first
            var data = LdapFilter.GetLdapFilter(_options.CollectMethod, _options.ExcludeDC, _options.Stealth);
            var ldapFilter = data.Filter;
            var props = data.Properties;
            var c = _options.CollectMethod;


            foreach (var domainName in _utils.GetDomainList())
            {
                _noPing = 0;
                _timeouts = 0;
                Console.WriteLine($"Starting enumeration for {domainName}");

                _watch = Stopwatch.StartNew();
                _currentDomain = domainName;
                _currentDomainSid = _utils.GetDomainSid(domainName);
                _currentCount = 0;
                var outputQueue = new BlockingCollection<Wrapper<OutputBase>>();

                if (_options.ComputerFile == null)
                {
                    var inputQueue = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);

                    var taskhandles = new Task[_options.Threads];

                    var writer = _options.Uri == null
                        ? StartOutputWriter(outputQueue)
                        : StartRestWriter(outputQueue);

                    if (c.Equals(CollectionMethod.Trusts) ||
                        c.Equals(CollectionMethod.Default))
                    {
                        foreach (var domain in DomainTrustEnumeration.DoTrustEnumeration(domainName))
                        {
                            outputQueue.Add(new Wrapper<OutputBase> {Item = domain});
                        }
                        if (_options.CollectMethod.Equals(CollectionMethod.Trusts))
                        {
                            outputQueue.CompleteAdding();
                            writer.Wait();
                            continue;
                        }
                    }

                    if (c.Equals(CollectionMethod.Container))
                    {
                        foreach (var container in ContainerHelpers.GetContainersForDomain(domainName))
                        {
                            outputQueue.Add(new Wrapper<OutputBase> { Item = container });
                        }
                        if (_options.CollectMethod.Equals(CollectionMethod.Container))
                        {
                            outputQueue.CompleteAdding();
                            writer.Wait();
                            continue;
                        }
                    }

                    for (var i = 0; i < _options.Threads; i++)
                    {
                        taskhandles[i] = StartRunner(inputQueue, outputQueue);
                    }

                    _statusTimer.Start();

                    IEnumerable<Wrapper<SearchResultEntry>> items;

                    if ((c.Equals(CollectionMethod.ComputerOnly) || c.Equals(CollectionMethod.Session) ||
                         c.Equals(CollectionMethod.LocalGroup) || c.Equals(CollectionMethod.LoggedOn)) &&
                        _options.Ou != null)
                    {
                        items = _utils.DoWrappedSearch(ldapFilter, SearchScope.Subtree, props, domainName, _options.Ou);
                    }
                    else
                    {
                        items = _utils.DoWrappedSearch(ldapFilter, SearchScope.Subtree, props, domainName);
                    }

                    foreach (var item in items)
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
                else
                {
                    var inputQueue = new BlockingCollection<Wrapper<string>>(1000);

                    var taskhandles = new Task[_options.Threads];

                    var writer = _options.Uri == null ? StartOutputWriter(outputQueue) : StartRestWriter(outputQueue);

                    for (var i = 0; i < _options.Threads; i++)
                    {
                        taskhandles[i] = StartCompListRunner(inputQueue, outputQueue);
                    }

                    _statusTimer.Start();

                    using (var reader = new StreamReader(_options.ComputerFile))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            inputQueue.Add(new Wrapper<string> {Item = line});
                        }
                        inputQueue.CompleteAdding();
                    }
                    Utils.Verbose("Waiting for enumeration threads to finish");
                    Task.WaitAll(taskhandles);

                    _statusTimer.Stop();
                    PrintStatus();
                    outputQueue.CompleteAdding();
                    Utils.Verbose("Waiting for writer thread to finish");
                    writer.Wait();
                    _watch.Stop();
                    Console.WriteLine($"Finished enumeration for {domainName} in {_watch.Elapsed}");
                    Console.WriteLine($"{_noPing} hosts failed ping. {_timeouts} hosts timedout.");
                    _watch = null;
                }
                
            }

            if (!_options.CollectMethod.Equals(CollectionMethod.SessionLoop)) return;
            if (_options.MaxLoopTime != null)
            {
                if (DateTime.Now > _options.LoopEnd)
                {
                    Console.WriteLine("Exiting session loop as LoopEndTime as passed");
                    return;
                }
            }

            Console.WriteLine($"Starting next session run in {_options.LoopTime} minutes");
            new ManualResetEvent(false).WaitOne(_options.LoopTime * 60 * 1000);
            if (_options.MaxLoopTime != null)
            {
                if (DateTime.Now > _options.LoopEnd)
                {
                    Console.WriteLine("Exiting session loop as LoopEndTime as passed");
                    return;
                }
            }
            Console.WriteLine("Starting next enumeration loop");
            StartEnumeration();
        }

        private Task StartRunner(BlockingCollection<Wrapper<SearchResultEntry>> processQueue, BlockingCollection<Wrapper<OutputBase>> writeQueue)
        {
            return Task.Factory.StartNew(() =>
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
                        case CollectionMethod.ObjectProps:
                            {
                                OutputBase props;
                                if (resolved.ObjectType.Equals("computer"))
                                {
                                    props = ObjectPropertyHelpers.GetComputerProps(entry, resolved);
                                }
                                else
                                {
                                    props = ObjectPropertyHelpers.GetUserProps(entry, resolved);
                                }

                                if (props != null)
                                    writeQueue.Add(new Wrapper<OutputBase> { Item = props });
                            }
                            break;
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

                                if (_options.Ou != null && !entry.DistinguishedName.Contains(_options.Ou))
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

        private Task StartCompListRunner(BlockingCollection<Wrapper<string>> input,
            BlockingCollection<Wrapper<OutputBase>> output)
        {
            return Task.Factory.StartNew(() =>
            {
                foreach (var wrapper in input.GetConsumingEnumerable())
                {
                    var item = wrapper.Item;

                    var resolved = _utils.ResolveHost(item);

                    if (!_utils.PingHost(resolved))
                    {
                        Interlocked.Increment(ref _currentCount);
                        Interlocked.Increment(ref _noPing);
                        continue;
                    }

                    var netbios = Utils.GetComputerNetbiosName(resolved);

                    var fullItem = new ResolvedEntry
                    {
                        BloodHoundDisplay = resolved,
                        ComputerSamAccountName = netbios
                    };

                    var c = _options.CollectMethod;

                    if (c.Equals(CollectionMethod.Session) ||
                        c.Equals(CollectionMethod.SessionLoop) ||
                        c.Equals(CollectionMethod.ComputerOnly))
                    {
                        try
                        {
                            var sessions = SessionHelpers.GetNetSessions(fullItem, _currentDomain);
                            foreach (var session in sessions)
                                output.Add(new Wrapper<OutputBase> {Item = session});
                        }
                        catch (TimeoutException)
                        {
                            Interlocked.Increment(ref _timeouts);
                        }
                        
                    }

                    if (c.Equals(CollectionMethod.LocalGroup) || c.Equals(CollectionMethod.ComputerOnly))
                    {
                        try
                        {
                            var admins = LocalAdminHelpers.GetSamAdmins(fullItem);
                            foreach (var admin in admins)
                                output.Add(new Wrapper<OutputBase> {Item = admin});
                        }
                        catch (TimeoutException)
                        {
                            Interlocked.Increment(ref _timeouts);
                        }
                    }

                    if (c.Equals(CollectionMethod.LoggedOn))
                    {
                        var sessions = SessionHelpers.GetNetLoggedOn(fullItem, _currentDomain);
                        sessions = sessions.Concat(SessionHelpers.GetRegistryLoggedOn(fullItem));

                        foreach (var session in sessions)
                            output.Add(new Wrapper<OutputBase> {Item = session});
                    }
                    Interlocked.Increment(ref _currentCount);
                    wrapper.Item = null;
                }
                
            });
        }

        private Task StartOutputWriter(BlockingCollection<Wrapper<OutputBase>> output)
        {
            return Task.Factory.StartNew(() =>
            {
                var adminCount = 0;
                var sessionCount = 0;
                var aclCount = 0;
                var groupCount = 0;
                var userPropsCount = 0;
                var compPropsCount = 0;
                var containerCount = 0;
                var gplinkCount = 0;

                StreamWriter admins = null;
                StreamWriter sessions = null;
                StreamWriter acls = null;
                StreamWriter groups = null;
                StreamWriter trusts = null;
                StreamWriter userprops = null;
                StreamWriter compprops = null;
                StreamWriter containers = null;
                StreamWriter gplinks = null;

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
                    }else if (item is Container)
                    {
                        if (containers == null)
                        {
                            var f = Utils.GetCsvFileName("container_structure.csv");
                            Utils.AddUsedFile(f);
                            var exists = File.Exists(f);
                            containers = new StreamWriter(f, exists);
                            if (!exists)
                                containers.WriteLine("ContainerType,ContainerName,ContainerGUID,ContainerBlocksInheritance,ObjectType,ObjectName");
                        }
                        containers.WriteLine(item.ToCsv());
                        containerCount++;
                        if (containerCount % 100 == 0)
                        {
                            containers.Flush();
                        }
                    }else if (item is GpLink)
                    {
                        if (gplinks == null)
                        {
                            var f = Utils.GetCsvFileName("container_gplinks.csv");
                            Utils.AddUsedFile(f);
                            var exists = File.Exists(f);
                            gplinks = new StreamWriter(f, exists);
                            if (!exists)
                                gplinks.WriteLine("ObjectType,ObjectName,ObjectGUID,GPODisplayName,GPOGuid,IsEnforced");
                        }
                        gplinks.WriteLine(item.ToCsv());
                        gplinkCount++;
                        if (gplinkCount % 100 == 0)
                        {
                            gplinks.Flush();
                        }
                    }
                    else if (item is UserProp)
                    {
                        if (userprops == null)
                        {
                            var f = Utils.GetCsvFileName("user_props.csv");
                            Utils.AddUsedFile(f);
                            var exists = File.Exists(f);
                            userprops = new StreamWriter(f, exists);
                            if (!exists)
                                userprops.WriteLine("AccountName,Enabled,PwdLastSet,LastLogon,Sid,SidHistory,HasSPN,ServicePrincipalNames");
                        }
                        userprops.WriteLine(item.ToCsv());
                        userPropsCount++;
                        if (userPropsCount % 100 == 0)
                        {
                            userprops.Flush();
                        }
                    }
                    else if (item is ComputerProp)
                    {
                        if (compprops == null)
                        {
                            var f = Utils.GetCsvFileName("computer_props.csv");
                            Utils.AddUsedFile(f);
                            var exists = File.Exists(f);
                            compprops = new StreamWriter(f, exists);
                            if (!exists)
                                compprops.WriteLine("AccountName,Enabled,PwdLastSet,LastLogon,OperatingSystem,Sid");
                        }
                        compprops.WriteLine(item.ToCsv());
                        compPropsCount++;
                        if (compPropsCount % 100 == 0)
                        {
                            compprops.Flush();
                        }
                    }
                    else if (item is Session)
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
                    }
                    else if (item is LocalAdmin)
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
                    }
                    else if (item is ACL)
                    {
                        if (acls == null)
                        {
                            var f = Utils.GetCsvFileName("acls.csv");
                            Utils.AddUsedFile(f);
                            var exists = File.Exists(f);
                            acls = new StreamWriter(f, exists);
                            if (!exists)
                                acls.WriteLine(
                                    "ObjectName,ObjectType,PrincipalName,PrincipalType,ActiveDirectoryRights,ACEType,AccessControlType,IsInherited");
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
                userprops?.Dispose();
                compprops?.Dispose();
                containers?.Dispose();
                gplinks?.Dispose();
            }, TaskCreationOptions.LongRunning);
        }

        private Task StartRestWriter(BlockingCollection<Wrapper<OutputBase>> output)
        {
            return Task.Factory.StartNew(() =>
            {
                var objectCount = 0;

                using (var client = new WebClient())
                {
                    client.Headers.Add("content-type", "application/json");
                    client.Headers.Add("Accept", "application/json; charset=UTF-8");
                    client.Headers.Add("Authorization", _options.GetEncodedUserPass());

                    var coll = new RestOutput();
                    var serializer = new JavaScriptSerializer();

                    foreach (var obj in output.GetConsumingEnumerable())
                    {
                        var item = obj.Item;

                        if (item is DomainTrust temp)
                        {
                            foreach (var x in temp.ToMultipleParam())
                            {
                                coll.AddNewData(temp.TypeHash(), x);
                            }
                        }
                        else
                        {
                            coll.AddNewData(item.TypeHash(), item.ToParam());
                        }
                        
                        obj.Item = null;
                        objectCount++;

                        if (objectCount % 500 != 0) continue;
                        var data = serializer.Serialize(coll.GetStatements());
                        client.UploadData(_options.GetURI(), "POST", Encoding.Default.GetBytes(data));
                        coll.Reset();
                    }
                    var remainingData = serializer.Serialize(coll.GetStatements());
                    var responseArray = client.UploadData(_options.GetURI(), "POST", Encoding.Default.GetBytes(remainingData));
                    //Console.WriteLine(Encoding.ASCII.GetString(responseArray));

                }
            }, TaskCreationOptions.LongRunning);
        }
    }
}
