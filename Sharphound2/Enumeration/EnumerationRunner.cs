using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
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
        private readonly string _currentDomainSid;

        public EnumerationRunner(Options opts)
        {
            _options = opts;
            _utils = Utils.Instance;
            _statusTimer = new System.Timers.Timer();
            _statusTimer.Elapsed += (sender, e) =>
            {
                //PrintStatus();
            };

            _statusTimer.AutoReset = false;
            _statusTimer.Interval = _options.Interval;
        }

        public void StartEnumeration()
        {
            //Let's determine what LDAP filter we need first
            string ldapFilter;
            switch (_options.CollectMethod)
            {
                case CollectionMethod.Group:
                    ldapFilter = "(|(memberof=*)(primarygroupid=*))";
                    break;
                case CollectionMethod.ComputerOnly:
                    ldapFilter = "(&(sAMAccountType = 805306369)(!(UserAccountControl: 1.2.840.113556.1.4.803:= 2)))";
                    break;
                case CollectionMethod.LocalGroup:
                    ldapFilter = "(&(sAMAccountType = 805306369)(!(UserAccountControl: 1.2.840.113556.1.4.803:= 2)))";
                    break;
                case CollectionMethod.GPOLocalGroup:
                    break;
                case CollectionMethod.Session:
                    ldapFilter = "(&(sAMAccountType = 805306369)(!(UserAccountControl: 1.2.840.113556.1.4.803:= 2)))";
                    break;
                case CollectionMethod.LoggedOn:
                    ldapFilter = "(&(sAMAccountType = 805306369)(!(UserAccountControl: 1.2.840.113556.1.4.803:= 2)))";
                    break;
                case CollectionMethod.Trusts:
                    break;
                case CollectionMethod.ACL:
                    ldapFilter =
                         "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectClass=domain))";
                    break;
                case CollectionMethod.SessionLoop:
                    break;
                case CollectionMethod.Default:
                    ldapFilter = "(|(memberof=*)(primarygroupid=*)(&(sAMAccountType = 805306369)(!(UserAccountControl: 1.2.840.113556.1.4.803:= 2))))";
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            foreach (var domainName in _utils.GetDomainList())
            {
                var outputQueue = new BlockingCollection<Wrapper<OutputBase>>();
                var inputQueue = new BlockingCollection<Wrapper<SearchResultEntry>>(1000);

                var scheduler = new LimitedConcurrencyLevelTaskScheduler(_options.Threads);
                var factory = new TaskFactory(scheduler);
                var taskhandles = new Task[_options.Threads];

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

                    switch (_options.CollectMethod)
                    {
                        case CollectionMethod.Group:
                            GroupHelpers.ProcessAdObject(entry, _currentDomainSid);
                            break;
                        case CollectionMethod.ComputerOnly:
                            break;
                        case CollectionMethod.LocalGroup:
                            break;
                        case CollectionMethod.GPOLocalGroup:
                            break;
                        case CollectionMethod.Session:
                            break;
                        case CollectionMethod.LoggedOn:
                            break;
                        case CollectionMethod.Trusts:
                            break;
                        case CollectionMethod.ACL:
                            break;
                        case CollectionMethod.SessionLoop:
                            break;
                        case CollectionMethod.Default:
                            break;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }
                }
            });
        }
    }
}
