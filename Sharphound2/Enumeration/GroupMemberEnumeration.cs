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
using static Sharphound2.Sharphound;

namespace Sharphound2.Enumeration
{
    internal class GroupMemberEnumeration
    {
        private readonly Utils _utils;
        private readonly Cache _cache;
        private readonly Options _options;
        private int _lastCount;
        private int _currentCount;
        private readonly System.Timers.Timer _statusTimer;
        

        public GroupMemberEnumeration(Options opt)
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
            _statusTimer.Interval = _options.StatusInterval;
        }

        public void StartEnumeration()
        {
            foreach (var domainName in _utils.GetDomainList())
            {
                var watch = Stopwatch.StartNew();
                Console.WriteLine($"Started group member enumeration for {domainName}");

                var OutputQueue = new BlockingCollection<Wrapper<GroupMember>>();
                var InputQueue = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);

                var scheduler = new LimitedConcurrencyLevelTaskScheduler(_options.Threads);
                var factory = new TaskFactory(scheduler);
                var taskhandles = new Task[_options.Threads];

                //Get the sid for the domain once so we can save processing later. Also saves network by omitting objectsid from our searcher
                var dsid = _utils.GetDomainSid(domainName);

                var writer = StartOutputWriter(factory, OutputQueue);
                for (var i = 0; i < _options.Threads; i++)
                {
                    taskhandles[i] = StartDataProcessor(factory, InputQueue, OutputQueue, dsid);
                }

                var searchRequest = 
                    _utils.GetSearchRequest("(|(memberof=*)(primarygroupid=*))",
                    SearchScope.Subtree,
                    new[] { "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid", "memberof", "serviceprincipalname" },
                    domainName);

                if (searchRequest == null)
                {
                    Console.WriteLine($"Unable to contact {domainName}");
                    continue;
                }

                var TimeoutCount = 0;
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

                        if (response == null) continue;
                        var pageResponse =
                            (PageResultResponseControl)response.Controls[0];

                        foreach (SearchResultEntry entry in response.Entries)
                        {
                            InputQueue.Add(new Wrapper<SearchResultEntry>
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
                        connection = _utils.GetLdapConnection(domainName);
                        if (TimeoutCount == 3)
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
                InputQueue.CompleteAdding();
                Task.WaitAll(taskhandles);
                OutputQueue.CompleteAdding();
                writer.Wait();
                watch.Stop();
                Console.WriteLine($"{domainName} finished in {watch.Elapsed}");
                watch.Reset();
                _statusTimer.Stop();
            }
            _statusTimer.Dispose();
        }

        private void PrintStatus()
        {
            var l = _lastCount;
            var c = _currentCount;
            var d = _currentCount - _lastCount;
            var progressStr = $"Status: {c} objects enumerated (+{c - l} {(float)d / (_options.StatusInterval / 1000)}/s --- Using {Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024 } MB RAM )";
            Console.WriteLine(progressStr);
            _lastCount = _currentCount;
            _statusTimer.Start();
        }

        private Task StartOutputWriter(TaskFactory factory, BlockingCollection<Wrapper<GroupMember>> output)
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

        private Task StartDataProcessor(TaskFactory factory, BlockingCollection<Wrapper<SearchResultEntry>> input, BlockingCollection<Wrapper<GroupMember>> output, string DomainSid)
        {
            return factory.StartNew(() =>
            {
                
            });
        }

        
    }
}
