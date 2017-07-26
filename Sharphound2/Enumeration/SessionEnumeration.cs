using Sharphound2.OutputObjects;
using SharpHound2;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Messaging;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using static Sharphound2.Sharphound;
using SearchOption = System.DirectoryServices.Protocols.SearchOption;

namespace Sharphound2.Enumeration
{
    internal class SessionEnumeration
    {
        private readonly Utils _utils;
        private readonly Cache _cache;
        private readonly Options _options;
        private int _lastCount;
        private int _currentCount;
        readonly System.Timers.Timer _statusTimer;
        private readonly string _currentUser;
        

        public SessionEnumeration(Options opt)
        {
            _utils = Utils.Instance;
            _cache = Cache.Instance;
            _options = opt;
            _statusTimer = new System.Timers.Timer();
            _statusTimer.Elapsed += (sender, e) =>
            {
                PrintStatus();
            };

            _statusTimer.AutoReset = false;
            _statusTimer.Interval = _options.Interval;
            _currentUser = WindowsIdentity.GetCurrent().Name.Split('\\')[1];
        }

        public void StartEnumeration()
        {
            foreach (var domainName in _utils.GetDomainList())
            {
                var watch = Stopwatch.StartNew();
                Console.WriteLine($"Started session enumeration for {domainName}");

                var outputQueue = new BlockingCollection<Wrapper<Session>>();
                var inputQueue = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);

                var scheduler = new LimitedConcurrencyLevelTaskScheduler(_options.Threads);
                var factory = new TaskFactory(scheduler);
                var taskhandles = new Task[_options.Threads];

                var writer = StartOutputWriter(factory, outputQueue);
                for (var i = 0; i < _options.Threads; i++)
                {
                    taskhandles[i] = StartDataProcessor(factory, inputQueue, outputQueue, domainName);
                }

                var searchRequest =
                    _utils.GetSearchRequest(
                        "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
                        SearchScope.Subtree,
                        new[]
                        {
                            "dnshostname", "samaccounttype", "distinguishedname", "primarygroupid", "samaccountname",
                            "objectsid"
                        },
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

        }

        private Task StartOutputWriter(TaskFactory factory, BlockingCollection<Wrapper<Session>> output)
        {
            return factory.StartNew(() =>
            {
                var path = "sessions.csv";
                var append = File.Exists(path);
                using (var writer = new StreamWriter(path, append))
                {
                    if (!append)
                    {
                        writer.WriteLine("UserName,ComputerName,Weight");
                    }
                    var localcount = 0;
                    foreach (var w in output.GetConsumingEnumerable())
                    {
                        var info = w.Item;
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

        private Task StartDataProcessor(TaskFactory factory, BlockingCollection<Wrapper<SearchResultEntry>> input, BlockingCollection<Wrapper<Session>> output, string domainName)
        {
            return factory.StartNew(() =>
            {
                foreach (var e in input.GetConsumingEnumerable())
                {
                    SearchResultEntry entry = e.Item;

                    var hostname = entry.ResolveBloodhoundDisplay();

                    if (!_utils.PingHost(hostname))
                    {
                        Interlocked.Increment(ref _currentCount);
                        continue;
                    }

                    List<Session> results;
                    if (_options.CollectMethod.Equals(CollectionMethod.LoggedOn))
                    {
                        var samAccountName = entry.GetProp("samaccountname");
                        results = SessionHelpers.GetNetLoggedOn(hostname, samAccountName, domainName);
                        results.AddRange(SessionHelpers.GetRegistryLoggedOn(hostname, samAccountName));
                    }
                    else
                    {
                        results = SessionHelpers.GetNetSessions(hostname, domainName);
                    }
                    foreach (var sess in results)
                    {
                        output.Add(new Wrapper<Session>{Item = sess});
                    }
                    Interlocked.Increment(ref _currentCount);
                }
            });
        }

        
    }
}
