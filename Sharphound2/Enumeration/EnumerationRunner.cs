using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Sharphound2.JsonObjects;
using static Sharphound2.Sharphound;
using Session = Sharphound2.JsonObjects.Session;

namespace Sharphound2.Enumeration
{
    internal class EnumerationRunner
    {
        private int _lastCount;
        private int _currentCount;
        private readonly Options _options;
        private readonly System.Timers.Timer _statusTimer;
        private readonly Utils _utils;
        private Stopwatch _watch;
        private bool _cancelled = false;
        private readonly CancellationTokenSource _cancellationToken;

        private int _noPing;
        private int _timeouts;
        private readonly ConcurrentQueue<GroupMember> _entDcs;

        public EnumerationRunner(Options opts)
        {
            _options = opts;
            _utils = Utils.Instance;
            _entDcs = new ConcurrentQueue<GroupMember>();
            _statusTimer = new System.Timers.Timer();
            _statusTimer.Elapsed += (sender, e) =>
            {
                PrintStatus();
            };

            _cancellationToken = new CancellationTokenSource();
            Console.CancelKeyPress += CancelHandler;
            
            _statusTimer.AutoReset = false;
            _statusTimer.Interval = _options.StatusInterval;
        }

        private void PrintStatus()
        {
            var l = _lastCount;
            var c = _currentCount;
            var progressStr =
                $"Status: {c} objects enumerated (+{c - l} {(float) c / (_watch.ElapsedMilliseconds / 1000)}/s --- Using {Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024} MB RAM )";
            Console.WriteLine(progressStr);
            _lastCount = _currentCount;
            _statusTimer.Start();
        }

        internal void StartStealthEnumeration()
        {
            var output = new BlockingCollection<Wrapper<JsonBase>>();
            var writer = StartOutputWriter(output);
            foreach (var domainName in _utils.GetDomainList())
            {
                Extensions.SetPrimaryDomain(domainName);
                
                _currentCount = 0;
                _timeouts = 0;
                _noPing = 0;
                _watch = Stopwatch.StartNew();
                
                Console.WriteLine($"Starting Stealth Enumeration for {domainName}");
                _statusTimer.Start();

                var domainSid = _utils.GetDomainSid(domainName);
                var res = _options.ResolvedCollMethods;
                var data = LdapFilter.BuildLdapData(res, _options.ExcludeDC, _options.LdapFilter);

                ContainerHelpers.BuildGpoCache(domainName);

                foreach (var entry in _utils.DoSearch(data.Filter, SearchScope.Subtree, data.Properties, domainName))
                {
                    if (_cancelled)
                    {
                        //output.CompleteAdding();
                        break;
                    }
                    var resolved = entry.ResolveAdEntry();
                    _currentCount++;
                    if (resolved == null)
                        continue;

                    var domain = Utils.ConvertDnToDomain(entry.DistinguishedName).ToUpper();
                    var sid = entry.GetSid();

                    if (resolved.ObjectType == "user")
                    {
                        var obj = new User
                        {
                            Name = resolved.BloodHoundDisplay
                        };

                        obj.Properties.Add("domain", domain);
                        obj.Properties.Add("objectsid", sid);
                        obj.Properties.Add("highvalue", false);

                        ObjectPropertyHelpers.GetProps(entry, resolved, ref obj);
                        GroupHelpers.GetGroupInfo(entry, resolved, domainSid, ref obj);
                        AclHelpers.GetObjectAces(entry, resolved, ref obj);

                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }else if (resolved.ObjectType == "group")
                    {
                        var obj = new Group
                        {
                            Name = resolved.BloodHoundDisplay
                        };
                        
                        obj.Properties.Add("domain", domain);
                        obj.Properties.Add("objectsid", sid);

                        if (sid.EndsWith("-512") || sid.EndsWith("-516") || sid.EndsWith("-519") ||
                            sid.EndsWith("-520") || sid.Equals("S-1-5-32-544") || sid.Equals("S-1-5-32-550") ||
                            sid.Equals("S-1-5-32-549") || sid.Equals("S-1-5-32-551") || sid.Equals("S-1-5-32-548"))
                        {
                            obj.Properties.Add("highvalue", true);  
                        }
                        else
                        {
                            obj.Properties.Add("highvalue", false);
                        }

                        ObjectPropertyHelpers.GetProps(entry, resolved, ref obj);
                        GroupHelpers.GetGroupInfo(entry, resolved, domainSid, ref obj);
                        AclHelpers.GetObjectAces(entry, resolved, ref obj);

                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }
                    else if (resolved.ObjectType == "computer")
                    {
                        var obj = new Computer
                        {
                            Name = resolved.BloodHoundDisplay,
                        };


                        obj.Properties.Add("domain", domain);
                        obj.Properties.Add("objectsid", sid);
                        obj.Properties.Add("highvalue", false);
                        var hasLaps = entry.GetProp("ms-mcs-admpwdexpirationtime") != null;
                        obj.Properties.Add("haslaps", hasLaps);

                        if (entry.DistinguishedName.ToLower().Contains("domain controllers"))
                        {
                            _entDcs.Enqueue(new GroupMember
                            {
                                MemberType = "computer",
                                MemberName = resolved.BloodHoundDisplay
                            });
                        }

                        ObjectPropertyHelpers.GetProps(entry, resolved, ref obj);
                        GroupHelpers.GetGroupInfo(entry, resolved, domainSid, ref obj);
                        AclHelpers.GetObjectAces(entry, resolved, ref obj);

                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }
                    else if (resolved.ObjectType == "domain")
                    {
                        var obj = new Domain
                        {
                            Name = resolved.BloodHoundDisplay,
                        };

                        obj.Properties.Add("objectsid", sid);
                        obj.Properties.Add("highvalue", true);

                        ObjectPropertyHelpers.GetProps(entry, resolved, ref obj);
                        AclHelpers.GetObjectAces(entry, resolved, ref obj);
                        ContainerHelpers.ResolveContainer(entry, resolved, ref obj);
                        TrustHelpers.DoTrustEnumeration(resolved, ref obj);

                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }
                    else if (resolved.ObjectType == "gpo")
                    {
                        var obj = new Gpo
                        {
                            Name = resolved.BloodHoundDisplay,
                            Guid = entry.GetProp("name").Replace("{", "").Replace("}", "")
                        };

                        obj.Properties.Add("highvalue", false);

                        AclHelpers.GetObjectAces(entry, resolved, ref obj);

                        foreach (var a in LocalGroupHelpers.GetGpoMembers(entry, domain))
                        {
                            output.Add(new Wrapper<JsonBase>
                            {
                                Item = a
                            });
                        }

                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }
                    else if (resolved.ObjectType == "ou")
                    {
                        var obj = new Ou
                        {
                            Guid = new Guid(entry.GetPropBytes("objectguid")).ToString().ToUpper()
                        };

                        obj.Properties.Add("name", resolved.BloodHoundDisplay.ToUpper());
                        obj.Properties.Add("highvalue", false);

                        ContainerHelpers.ResolveContainer(entry, resolved, ref obj);

                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }
                }

                if (Utils.IsMethodSet(ResolvedCollectionMethod.Session))
                {
                    Console.WriteLine("Doing stealth session enumeration");
                    foreach (var target in SessionHelpers.CollectStealthTargets(domainName))
                    {
                        if (!_utils.PingHost(target.BloodHoundDisplay))
                        {
                            _noPing++;
                            continue;
                        }

                        try
                        {
                            foreach (var session in SessionHelpers.GetNetSessions(target, domainName))
                            {
                                output.Add(new Wrapper<JsonBase>
                                {
                                    Item = session
                                });
                            }
                        }
                        catch (TimeoutException)
                        {
                            _timeouts++;
                        }
                    }
                }

                if (_entDcs.Count > 0)
                {
                    var dObj = _utils.GetForest(domainName);
                    var d = dObj == null ? domainName : dObj.RootDomain.Name;
                    var n = $"ENTERPRISE DOMAIN CONTROLLERS@{d}";
                    var obj = new Group
                    {
                        Name = n,
                        Members = _entDcs.ToArray()
                    };

                    obj.Properties.Add("domain", d);
                    obj.Properties.Add("objectsid", "S-1-5-9");
                    obj.Properties.Add("highvalue", true);

                    output.Add(new Wrapper<JsonBase>
                    {
                        Item = obj
                    });
                }

                
                PrintStatus();
                _statusTimer.Stop();

                Console.WriteLine($"Finished stealth enumeration for {domainName} in {_watch.Elapsed}");
                Console.WriteLine($"{_noPing} hosts failed ping. {_timeouts} hosts timedout.");
            }
            output.CompleteAdding();
            Utils.Verbose("Waiting for writer thread to finish");
            writer.Wait();
        }

        internal void StartCompFileEnumeration()
        {
            _noPing = 0;
            _timeouts = 0;
            _currentCount = 0;
            Console.WriteLine($"Starting CompFile Enumeration");

            _watch = Stopwatch.StartNew();

            var output = new BlockingCollection<Wrapper<JsonBase>>();
            var input = new BlockingCollection<Wrapper<string>>(1000);
            var taskHandles = new Task[_options.Threads];
            var writer = StartOutputWriter(output);
            
            for (var i = 0; i < _options.Threads; i++)
            {
                taskHandles[i] = StartListRunner(input, output);
            }

            _statusTimer.Start();

            using (var reader = new StreamReader(_options.ComputerFile))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (_cancelled)
                    {
                        input.CompleteAdding();
                        break;
                    }
                    input.Add(new Wrapper<string>
                    {
                        Item = line
                    });
                }
            }

            input.CompleteAdding();
            Utils.Verbose("Waiting for enumeration threads to finish");
            Task.WaitAll(taskHandles);

            PrintStatus();
            _statusTimer.Stop();
            //_statusTimer.Dispose();
            
            output.CompleteAdding();
            Utils.Verbose("Waiting for writer thread to finish");
            writer.Wait();
            _watch.Stop();
            Console.WriteLine($"Finished CompFile enumeration in {_watch.Elapsed}");
            Console.WriteLine($"{_noPing} hosts failed ping. {_timeouts} hosts timedout.");
            _watch = null;

            if ((_options.ResolvedCollMethods & ResolvedCollectionMethod.SessionLoop) == 0)
            {
                return;
            }

        
            _options.SessionLoopRunning = true;
            _options.ResolvedCollMethods = ResolvedCollectionMethod.SessionLoop;
            Console.WriteLine();
            Console.WriteLine("---------------------------");
            Console.WriteLine("Starting Session Loop Mode.");
            Console.WriteLine("---------------------------");
            Console.WriteLine();
            new ManualResetEvent(false).WaitOne(1000);
            StartListSessionLoopEnumeration();
        }

        internal void StartSessionLoopEnumeration()
        {
            var output = new BlockingCollection<Wrapper<JsonBase>>();
            var writer = StartOutputWriter(output);
            while (true)
            {
                foreach (var domain in _utils.GetDomainList())
                {
                    Extensions.SetPrimaryDomain(domain);
                    _noPing = 0;
                    _timeouts = 0;
                    _currentCount = 0;
                    Console.WriteLine($"Starting Enumeration for {domain}");

                    _watch = Stopwatch.StartNew();

                    if (_options.Stealth)
                    {
                        foreach (var target in SessionHelpers.CollectStealthTargets(domain))
                        {
                            if (!_utils.PingHost(target.BloodHoundDisplay))
                            {
                                _noPing++;
                                continue;
                            }
                            
                            try
                            {
                                foreach (var s in SessionHelpers.GetNetSessions(target, domain))
                                {
                                    output.Add(new Wrapper<JsonBase>
                                    {
                                        Item = s
                                    });
                                }
                            }
                            catch (TimeoutException)
                            {
                                _timeouts++;
                            }

                            PrintStatus();
                            _watch.Stop();
                            Console.WriteLine($"Finished enumeration for {domain} in {_watch.Elapsed}");
                            Console.WriteLine($"{_noPing} hosts failed ping. {_timeouts} hosts timedout.");
                            _watch = null;
                        }
                    }
                    else
                    {
                        var input = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);
                        var taskHandles = new Task[_options.Threads];
                        var ldapData = LdapFilter.BuildLdapData(_options.ResolvedCollMethods, _options.ExcludeDC, _options.LdapFilter);

                        for (var i = 0; i < _options.Threads; i++)
                        {
                            taskHandles[i] = StartRunner(input, output);
                        }

                        _statusTimer.Start();

                        foreach (var item in _utils.DoWrappedSearch(ldapData.Filter, SearchScope.Subtree, ldapData.Properties,
                            domain, _options.Ou))
                        {
                            if (_cancelled)
                            {
                                input.CompleteAdding();
                                break;
                            }
                            input.Add(item);
                        }

                        input.CompleteAdding();
                        Utils.Verbose("Waiting for enumeration threads to finish");
                        Task.WaitAll(taskHandles);

                        PrintStatus();
                        _statusTimer.Stop();
                        
                        _watch.Stop();
                        Console.WriteLine($"Finished enumeration for {domain} in {_watch.Elapsed}");
                        Console.WriteLine($"{_noPing} hosts failed ping. {_timeouts} hosts timedout.");
                        _watch = null;
                    }
                }

                if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
                {
                    Console.WriteLine("User pressed escape, exiting session loop");
                    //output.CompleteAdding();
                    writer.Wait();
                    break;
                }

                if (_options.MaxLoopTime != null)
                {
                    if (DateTime.Now > _options.LoopEnd)
                    {
                        Console.WriteLine("Exiting session loop as LoopEndTime has passed.");
                        //output.CompleteAdding();
                        writer.Wait();
                        break;
                    }
                }

                Console.WriteLine($"Starting next session run in {_options.LoopDelay} seconds");
                WaitHandle.WaitAny(new[] {_cancellationToken.Token.WaitHandle}, _options.LoopDelay * 1000);

                if (_options.MaxLoopTime != null)
                {
                    if (DateTime.Now > _options.LoopEnd)
                    {
                        Console.WriteLine("Exiting session loop as LoopEndTime has passed.");
                        output.CompleteAdding();
                        writer.Wait();
                        break;
                    }
                }

                if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
                {
                    Console.WriteLine("User pressed escape, exiting session loop");
                    output.CompleteAdding();
                    writer.Wait();
                    break;
                }

                if (_cancelled)
                {
                    output.CompleteAdding();
                    writer.Wait();
                    break;
                }

                Console.WriteLine("Starting next session loop");
            }
        }

        internal void StartListSessionLoopEnumeration()
        {
            var output = new BlockingCollection<Wrapper<JsonBase>>();
            var writer = StartOutputWriter(output);
            while (true)
            {
                foreach (var domain in _utils.GetDomainList())
                {
                    Extensions.SetPrimaryDomain(domain);
                    _noPing = 0;
                    _timeouts = 0;
                    _currentCount = 0;
                    Console.WriteLine($"Starting Enumeration for {domain}");

                    _watch = Stopwatch.StartNew();


                    var input = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);
                    var taskHandles = new Task[_options.Threads];
                    var ldapData = LdapFilter.BuildLdapData(_options.ResolvedCollMethods, _options.ExcludeDC, _options.LdapFilter);

                    ContainerHelpers.BuildGpoCache(domain);

                    for (var i = 0; i < _options.Threads; i++)
                    {
                        taskHandles[i] = StartRunner(input, output);
                    }

                    _statusTimer.Start();

                    foreach (var item in _utils.DoWrappedSearch(ldapData.Filter, SearchScope.Subtree, ldapData.Properties,
                        domain, _options.Ou))
                    {
                        if (_cancelled)
                        {
                            input.CompleteAdding();
                            break;
                        }
                        input.Add(item);
                    }

                    input.CompleteAdding();
                    Utils.Verbose("Waiting for enumeration threads to finish");
                    Task.WaitAll(taskHandles);

                    _statusTimer.Stop();
                    PrintStatus();
                    output.CompleteAdding();
                    _watch.Stop();
                    Console.WriteLine($"Finished enumeration for {domain} in {_watch.Elapsed}");
                    Console.WriteLine($"{_noPing} hosts failed ping. {_timeouts} hosts timedout.");
                    _watch = null;
                }

                if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
                {
                    Console.WriteLine("User pressed escape, exiting session loop");
                    output.CompleteAdding();
                    writer.Wait();
                    break;
                }

                if (_options.MaxLoopTime != null)
                {
                    if (DateTime.Now > _options.LoopEnd)
                    {
                        Console.WriteLine("Exiting session loop as LoopEndTime has passed.");
                        output.CompleteAdding();
                        writer.Wait();
                        break;
                    }
                }

                Console.WriteLine($"Starting next session run in {_options.LoopDelay} seconds");
                WaitHandle.WaitAny(new[] {_cancellationToken.Token.WaitHandle}, _options.LoopDelay * 1000);

                if (_options.MaxLoopTime != null)
                {
                    if (DateTime.Now > _options.LoopEnd)
                    {
                        Console.WriteLine("Exiting session loop as LoopEndTime has passed.");
                        output.CompleteAdding();
                        writer.Wait();
                        break;
                    }
                }

                if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
                {
                    Console.WriteLine("User pressed escape, exiting session loop");
                    output.CompleteAdding();
                    writer.Wait();
                    break;
                }

                if (_cancelled)
                {
                    output.CompleteAdding();
                    writer.Wait();
                    break;
                }

                Console.WriteLine("Starting next session loop");
            }
        }

        internal void StartEnumeration()
        {
            var output = new BlockingCollection<Wrapper<JsonBase>>();
            var writer = StartOutputWriter(output);
            foreach (var domain in _utils.GetDomainList())
            {
                Extensions.SetPrimaryDomain(domain);
                _noPing = 0;
                _timeouts = 0;
                _currentCount = 0;
                Console.WriteLine($"Starting Enumeration for {domain}");

                _watch = Stopwatch.StartNew();
                
                
                var input = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);
                var taskHandles = new Task[_options.Threads];
                var ldapData = LdapFilter.BuildLdapData(_options.ResolvedCollMethods, _options.ExcludeDC, _options.LdapFilter);

                ContainerHelpers.BuildGpoCache(domain);

                for (var i = 0; i < _options.Threads; i++)
                {
                    taskHandles[i] = StartRunner(input, output);
                }

                _statusTimer.Start();

                foreach (var item in _utils.DoWrappedSearch(ldapData.Filter, SearchScope.Subtree, ldapData.Properties,
                    domain, _options.Ou))
                {
                    if (_cancelled)
                    {
                        input.CompleteAdding();
                        break;
                    }
                    input.Add(item);
                }

                input.CompleteAdding();
                Utils.Verbose("Waiting for enumeration threads to finish");
                Task.WaitAll(taskHandles);

                if (_entDcs.Count > 0)
                {
                    var dObj = _utils.GetForest(domain);
                    var d = dObj == null ? domain : dObj.RootDomain.Name;
                    var n = $"ENTERPRISE DOMAIN CONTROLLERS@{d}";
                    var obj = new Group
                    {
                        Name = n,
                        Members = _entDcs.ToArray()
                    };

                    obj.Properties.Add("domain", d);
                    obj.Properties.Add("objectsid", "S-1-5-9");
                    obj.Properties.Add("highvalue", true);

                    output.Add(new Wrapper<JsonBase>
                    {
                        Item = obj
                    });
                }

                _statusTimer.Stop();
                //_statusTimer.Dispose();
                PrintStatus();
                _watch.Stop();
                Console.WriteLine($"Finished enumeration for {domain} in {_watch.Elapsed}");
                Console.WriteLine($"{_noPing} hosts failed ping. {_timeouts} hosts timedout.");
                _watch = null;
            }

            output.CompleteAdding();
            Utils.Verbose("Waiting for writer thread to finish");
            writer.Wait();

            if ((_options.ResolvedCollMethods & ResolvedCollectionMethod.SessionLoop) == 0)
            {
                return;
            }
    
            _options.SessionLoopRunning = true;
            _options.ResolvedCollMethods = ResolvedCollectionMethod.SessionLoop;
            Console.WriteLine();
            Console.WriteLine("---------------------------");
            Console.WriteLine("Starting Session Loop Mode.");
            Console.WriteLine("---------------------------");
            Console.WriteLine();
            new ManualResetEvent(false).WaitOne(1000);
            StartSessionLoopEnumeration();
        }

        protected void CancelHandler(object sender, ConsoleCancelEventArgs args)
        {
            args.Cancel = true;
            _cancelled = true;
            _cancellationToken.Cancel();
            Console.WriteLine("Caught Ctrl + C, Waiting for cleanup");
        }

        private Task StartOutputWriter(BlockingCollection<Wrapper<JsonBase>> outputQueue)
        {
            return Task.Factory.StartNew(() =>
            {
                var serializer = new JsonSerializer
                {
                    NullValueHandling = NullValueHandling.Include,
                };
                var computerCount = 0;
                var userCount = 0;
                var groupCount = 0;
                var domainCount = 0;
                var gpoCount = 0;
                var ouCount = 0;
                var sessionCount = 0;
                var gpoAdminCount = 0;

                JsonTextWriter computers = null;
                JsonTextWriter users = null;
                JsonTextWriter groups = null;
                JsonTextWriter domains = null;
                JsonTextWriter gpos = null;
                JsonTextWriter ous = null;
                JsonTextWriter sessions = null;
                JsonTextWriter gpomembers = null;

                foreach (var obj in outputQueue.GetConsumingEnumerable())
                {
                    var item = obj.Item;
                    switch (item)
                    {
                        case Group g:
                            if (groups == null)
                                groups = CreateFileStream("groups");
                            
                            serializer.Serialize(groups, g);
                            groupCount++;
                            if (groupCount % 100 == 0)
                                groups.Flush();
                            break;
                        case Computer c:
                            if (computers == null)
                                computers = CreateFileStream("computers");

                            serializer.Serialize(computers, c);
                            computerCount++;
                            if (computerCount % 100 == 0)
                                computers.Flush();
                            break;
                        case User u:
                            if (users == null)
                                users = CreateFileStream("users");

                            serializer.Serialize(users, u);
                            userCount++;
                            if (userCount % 100 == 0)
                                users.Flush();
                            break;
                        case Domain d:
                            if (domains == null)
                                domains = CreateFileStream("domains");

                            serializer.Serialize(domains, d);
                            domainCount++;
                            if (domainCount % 100 == 0)
                                domains.Flush();
                            break;
                        case Gpo g:
                            if (gpos == null)
                                gpos = CreateFileStream("gpos");

                            serializer.Serialize(gpos, g);
                            gpoCount++;
                            if (gpoCount % 100 == 0)
                                gpos.Flush();
                            break;
                        case Ou o:
                            if (ous == null)
                                ous = CreateFileStream("ous");

                            serializer.Serialize(ous, o);
                            ouCount++;
                            
                            if (ouCount % 100 == 0)
                                ous.Flush();
                            break;
                        case Session s:
                            if (sessions == null)
                                sessions = CreateFileStream("sessions");

                            serializer.Serialize(sessions, s);
                            sessionCount++;

                            if (sessionCount % 100 == 0)
                                sessions.Flush();
                            break;
                        case GpoMember a:
                            if (gpomembers == null)
                                gpomembers = CreateFileStream("gpomembers");

                            serializer.Serialize(gpomembers, a);
                            gpoAdminCount++;
                            if (gpoAdminCount % 100 == 0)
                                gpomembers.Flush();
                            break;
                    }

                    obj.Item = null;
                }

                groups?.CloseC(groupCount,"groups");
                sessions?.CloseC(sessionCount,"sessions");
                computers?.CloseC(computerCount,"computers");
                users?.CloseC(userCount,"users");
                ous?.CloseC(ouCount, "ous");
                domains?.CloseC(domainCount, "domains");
                gpos?.CloseC(gpoCount, "gpos");
                gpomembers?.CloseC(gpoAdminCount,"gpomembers");
            }, TaskCreationOptions.LongRunning);
        }

        private JsonTextWriter CreateFileStream(string baseName)
        {
            var fileName = Utils.GetJsonFileName(baseName);
            Utils.AddUsedFile(fileName);
            var e = File.Exists(fileName);
            if (e)
            {
                throw new Exception($"File {fileName} already exists, throwing exception!");
            }
            var writer = new StreamWriter(fileName, false, Encoding.UTF8);
            var format = _options.PrettyJson ? Formatting.Indented : Formatting.None;
            var jw = new JsonTextWriter(writer) { Formatting = format };

            jw.WriteStartObject();
            jw.WritePropertyName(baseName);
            jw.WriteStartArray();

            return jw;
        }

        private Task StartListRunner(BlockingCollection<Wrapper<string>> input, BlockingCollection<Wrapper<JsonBase>> output)
        {
            return Task.Factory.StartNew(() =>
            {
                foreach (var wrapper in input.GetConsumingEnumerable())
                {
                    if (_cancelled)
                    {
                        output.CompleteAdding();
                        break;
                    }
                    var item = wrapper.Item;

                    var resolved = _utils.ResolveHost(item);
                    Interlocked.Increment(ref _currentCount);
                    if (resolved == null || !_utils.PingHost(resolved))
                    {
                        Interlocked.Increment(ref _noPing);
                        wrapper.Item = null;
                        continue;
                    }
                    
                    // make sure to have the computer FQDN in full uppercase, like in other collection methods (non-ComputerFile)
                    resolved = resolved.ToUpper();

                    var netbios = Utils.GetComputerNetbiosName(resolved, out var domain);
                    var temp = _utils.GetDomain(domain);
                    if (temp != null)
                    {
                        domain = temp.Name;
                    }

                    var full = new ResolvedEntry
                    {
                        BloodHoundDisplay = resolved,
                        ComputerSamAccountName = netbios,
                        ObjectType = "computer"
                    };

                    var obj = new Computer
                    {
                        Name = resolved
                    };

                    obj.Properties.Add("highvalue", false);
                    var timeout = false;

                    try
                    {
                        foreach (var s in SessionHelpers.GetNetSessions(full, domain))
                        {
                            output.Add(new Wrapper<JsonBase>
                            {
                                Item = s
                            });
                        }
                    }
                    catch (TimeoutException)
                    {
                        timeout = true;
                    }
                    
                    try
                    {
                        obj.LocalAdmins = LocalGroupHelpers
                            .GetGroupMembers(full, LocalGroupHelpers.LocalGroupRids.Administrators).ToArray();
                    }
                    catch (TimeoutException)
                    {
                        timeout = true;
                    }

                    try
                    {
                        obj.RemoteDesktopUsers = LocalGroupHelpers
                            .GetGroupMembers(full, LocalGroupHelpers.LocalGroupRids.RemoteDesktopUsers).ToArray();
                    }
                    catch (TimeoutException)
                    {
                        timeout = true;
                    }

                    try
                    {
                        obj.DcomUsers = LocalGroupHelpers
                            .GetGroupMembers(full, LocalGroupHelpers.LocalGroupRids.DcomUsers).ToArray();
                    }
                    catch (TimeoutException)
                    {
                        timeout = true;
                    }

                    try
                    {
                        foreach (var s in SessionHelpers.DoLoggedOnCollection(full, domain))
                        {
                            output.Add(new Wrapper<JsonBase>
                            {
                                Item = s
                            });
                        }
                    }
                    catch (TimeoutException)
                    {
                        timeout = true;
                    }

                    if (timeout)
                        Interlocked.Increment(ref _timeouts);

                    if (obj.LocalAdmins?.Length == 0)
                        obj.LocalAdmins = null;

                    if (obj.RemoteDesktopUsers?.Length == 0)
                        obj.RemoteDesktopUsers = null;

                    if (!_options.SessionLoopRunning)
                    {
                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }
                }
            });
        }

        private Task StartRunner(BlockingCollection<Wrapper<SearchResultEntry>> processQueue,
            BlockingCollection<Wrapper<JsonBase>> output)
        {
            return Task.Factory.StartNew(() =>
            {
                foreach (var wrapper in processQueue.GetConsumingEnumerable())
                {
                    if (_cancelled)
                    {
                        break;
                    }
                    var entry = wrapper.Item;
                    var resolved = entry.ResolveAdEntry();

                    if (resolved == null)
                    {
                        Interlocked.Increment(ref _currentCount);
                        wrapper.Item = null;
                        continue;
                    }

                    var innerTimer = Stopwatch.StartNew();
                    var innerElapse = new System.Timers.Timer {Interval = 30000};

                    innerElapse.Elapsed += (sender, args) => { Console.WriteLine($"Still processing {resolved.ObjectType} - {resolved.BloodHoundDisplay}: {innerTimer.ElapsedMilliseconds  / 1000}s"); };
                    innerElapse.AutoReset = true;
                    innerTimer.Start();
                    innerElapse.Start();
                    
                    var sid = entry.GetSid();
                    var domain = Utils.ConvertDnToDomain(entry.DistinguishedName).ToUpper();
                    var domainSid = _utils.GetDomainSid(domain);

                    if (resolved.ObjectType == "user")
                    {
                        var obj = new User
                        {
                            Name = resolved.BloodHoundDisplay
                        };

                        obj.Properties.Add("domain", domain);
                        obj.Properties.Add("objectsid", sid);
                        obj.Properties.Add("highvalue", false);

                        ObjectPropertyHelpers.GetProps(entry, resolved, ref obj);
                        GroupHelpers.GetGroupInfo(entry, resolved, domainSid, ref obj);
                        AclHelpers.GetObjectAces(entry, resolved, ref obj);
                        SPNHelpers.GetSpnTargets(entry, resolved, ref obj);

                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }else if (resolved.ObjectType == "group")
                    {
                        var obj = new Group
                        {
                            Name = resolved.BloodHoundDisplay
                        };

                        if (sid.EndsWith("-512") || sid.EndsWith("-516") || sid.EndsWith("-519") ||
                            sid.EndsWith("-520") || sid.Equals("S-1-5-32-544") || sid.Equals("S-1-5-32-550") ||
                            sid.Equals("S-1-5-32-549") || sid.Equals("S-1-5-32-551") || sid.Equals("S-1-5-32-548"))
                        {
                            obj.Properties.Add("highvalue", true);
                        }
                        else
                        {
                            obj.Properties.Add("highvalue", false);
                        }

                        obj.Properties.Add("domain", domain);
                        obj.Properties.Add("objectsid", sid);

                        ObjectPropertyHelpers.GetProps(entry, resolved, ref obj);
                        GroupHelpers.GetGroupInfo(entry, resolved, domainSid, ref obj);
                        AclHelpers.GetObjectAces(entry, resolved, ref obj);

                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }else if (resolved.ObjectType == "computer")
                    {
                        var obj = new Computer
                        {
                            Name = resolved.BloodHoundDisplay,
                            LocalAdmins = new LocalMember[]{},
                            RemoteDesktopUsers = new LocalMember[]{}
                        };

                        var hasLaps = entry.GetProp("ms-mcs-admpwdexpirationtime") != null;
                        obj.Properties.Add("haslaps", hasLaps);
                        obj.Properties.Add("objectsid", sid);
                        obj.Properties.Add("highvalue", false);
                        obj.Properties.Add("domain", domain);


                        if (Utils.IsMethodSet(ResolvedCollectionMethod.Group))
                        {
                            if (entry.DistinguishedName.ToLower().Contains("domain controllers"))
                            {
                                _entDcs.Enqueue(new GroupMember
                                {
                                    MemberName = resolved.BloodHoundDisplay,
                                    MemberType = "computer"
                                });
                            }
                        }
                        
                        ObjectPropertyHelpers.GetProps(entry, resolved, ref obj);
                        GroupHelpers.GetGroupInfo(entry, resolved, domainSid, ref obj);
                        AclHelpers.GetObjectAces(entry, resolved, ref obj);

                        if (!_utils.PingHost(resolved.BloodHoundDisplay))
                        {
                            Interlocked.Increment(ref _noPing);
                        }
                        else
                        {
                            var timeout = false;
                            try
                            {
                                obj.LocalAdmins = LocalGroupHelpers
                                    .GetGroupMembers(resolved, LocalGroupHelpers.LocalGroupRids.Administrators)
                                    .ToArray();
                            }
                            catch (TimeoutException)
                            {
                                timeout = true;
                            }

                            try
                            {
                                obj.RemoteDesktopUsers = LocalGroupHelpers.GetGroupMembers(resolved,
                                    LocalGroupHelpers.LocalGroupRids.RemoteDesktopUsers).ToArray();
                            }
                            catch (TimeoutException)
                            {
                                timeout = true;
                            }

                            try
                            {
                                obj.DcomUsers = LocalGroupHelpers.GetGroupMembers(resolved,
                                    LocalGroupHelpers.LocalGroupRids.DcomUsers).ToArray();
                            }
                            catch (TimeoutException)
                            {
                                timeout = true;
                            }

                            try
                            {
                                foreach (var s in SessionHelpers.GetNetSessions(resolved, domain))
                                {
                                    output.Add(new Wrapper<JsonBase>
                                    {
                                        Item = s
                                    });
                                }
                            }
                            catch (TimeoutException)
                            {
                                timeout = true;
                            }

                            try
                            {
                                foreach (var s in SessionHelpers.DoLoggedOnCollection(resolved, domain))
                                {
                                    output.Add(new Wrapper<JsonBase>
                                    {
                                        Item = s
                                    });
                                }
                            }
                            catch (TimeoutException)
                            {
                                timeout = true;
                            }

                            if (timeout)
                                Interlocked.Increment(ref _timeouts);
                        }

                        if (!_options.SessionLoopRunning)
                        {
                            output.Add(new Wrapper<JsonBase>
                            {
                                Item = obj
                            });
                        }
                    }
                    else if (resolved.ObjectType == "domain")
                    {
                        var obj = new Domain
                        {
                            Name = resolved.BloodHoundDisplay
                        };

                        obj.Properties.Add("objectsid", sid);
                        obj.Properties.Add("highvalue", true);
                        obj.Properties.Add("domain", domain);

                        ObjectPropertyHelpers.GetProps(entry, resolved, ref obj);
                        AclHelpers.GetObjectAces(entry, resolved, ref obj);
                        ContainerHelpers.ResolveContainer(entry, resolved, ref obj);
                        TrustHelpers.DoTrustEnumeration(resolved, ref obj);

                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }else if (resolved.ObjectType == "gpo")
                    {
                        var obj = new Gpo
                        {
                            Name = resolved.BloodHoundDisplay,
                            Guid = entry.GetProp("name").Replace("{", "").Replace("}", "")
                        };

                        obj.Properties.Add("highvalue", false);
                        obj.Properties.Add("domain", domain);

                        AclHelpers.GetObjectAces(entry, resolved, ref obj);
                        ObjectPropertyHelpers.GetProps(entry, resolved, ref obj);

                        foreach (var a in LocalGroupHelpers.GetGpoMembers(entry, domain))
                        {
                            output.Add(new Wrapper<JsonBase>
                            {
                                Item = a
                            });
                        }

                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }else if (resolved.ObjectType == "ou")
                    {
                        var obj = new Ou
                        {
                            Guid = new Guid(entry.GetPropBytes("objectguid")).ToString().ToUpper()
                        };

                        obj.Properties.Add("name", resolved.BloodHoundDisplay.ToUpper());
                        obj.Properties.Add("highvalue", false);
                        obj.Properties.Add("domain", domain);

                        ContainerHelpers.ResolveContainer(entry, resolved, ref obj);
                        ObjectPropertyHelpers.GetProps(entry, resolved, ref obj);

                        output.Add(new Wrapper<JsonBase>
                        {
                            Item = obj
                        });
                    }

                    innerTimer.Stop();
                    if (innerTimer.ElapsedMilliseconds > 30000)
                    {
                        Console.WriteLine($"Finished {resolved.BloodHoundDisplay}");
                    }

                    innerElapse.Stop();
                    innerElapse.Close();
                    

                    Interlocked.Increment(ref _currentCount);
                    wrapper.Item = null;
                }
            }, TaskCreationOptions.LongRunning);
        }
    }
}
