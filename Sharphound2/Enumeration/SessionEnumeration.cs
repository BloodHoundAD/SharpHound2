using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static Sharphound2.Sharphound;

namespace Sharphound2.Enumeration
{
    class SessionEnumeration
    {
        readonly Utils utils;
        readonly Options options;
        int LastCount;
        int CurrentCount;
        System.Timers.Timer timer;
    }
}
