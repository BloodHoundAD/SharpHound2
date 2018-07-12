using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class GpoAdmin : JsonBase
    {
        public string Server { get; set; }
        public string ObjectName { get; set; }
        public string ObjectType { get; set; }
    }
}
