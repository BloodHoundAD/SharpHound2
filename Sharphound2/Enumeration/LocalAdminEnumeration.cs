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
using System.Threading;
using System.Threading.Tasks;
using static Sharphound2.Sharphound;

namespace Sharphound2.Enumeration
{
    

    internal class LocalAdminEnumeration
    {
        private readonly Utils _utils;
        private readonly Options _options;
        private int _lastCount;
        private int _currentCount;
        private readonly System.Timers.Timer _statusTimer;

        public LocalAdminEnumeration(Options opt)
        {
            _utils = Utils.Instance;
            _options = opt;
            _statusTimer = new System.Timers.Timer();
            _statusTimer.Elapsed += (sender, e) =>
            {
                PrintStatus();
            };

            _statusTimer.AutoReset = false;
            _statusTimer.Interval = _options.Interval;
        }

        public void StartEnumeration()
        {
            foreach (var domainName in _utils.GetDomainList())
            {
                var watch = Stopwatch.StartNew();
                Console.WriteLine($"Started local admin enumeration for {domainName}");

                var outputQueue = new BlockingCollection<Wrapper<LocalAdmin>>();
                var inputQueue = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);

                var scheduler = new LimitedConcurrencyLevelTaskScheduler(_options.Threads);
                var factory = new TaskFactory(scheduler);
                var taskhandles = new Task[_options.Threads];

                //Get the sid for the domain once so we can save processing later. Also saves network by omitting objectsid from our searcher
                var dsid = new SecurityIdentifier(_utils.GetDomain(domainName).GetDirectoryEntry().Properties["objectsid"].Value as byte[], 0).ToString();

                var writer = StartOutputWriter(factory, outputQueue);
                for (var i = 0; i < _options.Threads; i++)
                {
                    taskhandles[i] = StartDataProcessor(factory, inputQueue, outputQueue, domainName, dsid);
                }

                var searchRequest =
                    _utils.GetSearchRequest("(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    new[] { "dnshostname", "samaccounttype", "distinguishedname", "primarygroupid", "samaccountname", "objectsid" },
                    domainName);

                if (searchRequest == null)
                {
                    Console.WriteLine($"Unable to contact {domainName}");
                    continue;
                }

                var timeoutCount = 0;
                var timeout = new TimeSpan(0, 0, 30);
                var connection = _utils.GetLdapConnection(domainName);

                _lastCount = 0;
                _currentCount = 0;

                _statusTimer.Start();

                //Add our paging control
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
                        //We hit a timeout. Add to a counter and add 30 seconds to the timeout
                        timeoutCount++;
                        connection = _utils.GetLdapConnection(domainName);
                        if (timeoutCount == 3)
                        {
                            //If we've timed out 4 times, just abort, cause something is weird.
                            Console.WriteLine("Aborting due to too many ldap timeouts");
                            break;
                        }
                        Console.WriteLine("Hit LDAP timeout, adding 30 seconds and retrying");
                        timeout = timeout.Add(new TimeSpan(0, 0, 30));
                        connection.Timeout = timeout;
                    }
                }

                connection.Dispose();
                inputQueue.CompleteAdding();
                Task.WaitAll(taskhandles);
                outputQueue.CompleteAdding();
                writer.Wait();
                watch.Stop();
                Console.WriteLine($"{domainName} finished in {watch.Elapsed}");
                watch.Reset();
            }
        }

        void PrintStatus()
        {
            var l = _lastCount;
            var c = _currentCount;
            var d = _currentCount - _lastCount;
            var progressStr = $"Status: {c} objects enumerated (+{c - l} {(float)d / (_options.Interval / 1000)}/s --- Using {Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024 } MB RAM )";
            Console.WriteLine(progressStr);
            _lastCount = _currentCount;
            _statusTimer.Start();
        }

        Task StartOutputWriter(TaskFactory factory, BlockingCollection<Wrapper<LocalAdmin>> output)
        {
            return factory.StartNew(() =>
            {
                var path = "local_admins.csv";
                var append = File.Exists(path);
                using (var writer = new StreamWriter(path, append))
                {
                    if (!append)
                    {
                        writer.WriteLine("ComputerName,AccountName,AccountType");
                    }
                    var localcount = 0;
                    foreach (var w in output.GetConsumingEnumerable())
                    {
                        var info = w.Item;
                        writer.WriteLine(info.ToCsv());
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

        private Task StartDataProcessor(TaskFactory factory, BlockingCollection<Wrapper<SearchResultEntry>> input,
            BlockingCollection<Wrapper<LocalAdmin>> output, string DomainName, string DomainSid)
        {
            return factory.StartNew(() =>
            {
                foreach (var e in input.GetConsumingEnumerable())
                {
                    var entry = e.Item;

                    var hostname = entry.ResolveBloodhoundDisplay();
                    if (!_utils.PingHost(hostname))
                    {
                        Interlocked.Increment(ref _currentCount);
                        continue;
                    }

                    var results = new List<LocalAdmin>();
                    try
                    {
                        results = LocalAdminHelpers.LocalGroupApi(hostname, "Administrators", DomainName, DomainSid);
                    }
                    catch (SystemDownException)
                    {

                    }
                    catch (ApiFailedException)
                    {
                        try
                        {
                            results = LocalAdminHelpers.LocalGroupWinNt(hostname, "Administrators");
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
                    Interlocked.Increment(ref _currentCount);
                    foreach (var la in results)
                    {
                        output.Add(new Wrapper<LocalAdmin>
                        {
                            Item = la
                        });
                    }
                }
            });
        }
    }
}
