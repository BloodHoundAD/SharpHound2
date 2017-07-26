using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Timers;
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
            foreach (var domainName in _utils.GetDomainList())
            {
                
            }
        }
    }
}
