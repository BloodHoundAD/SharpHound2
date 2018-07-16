using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class GpoAdmin : JsonBase
    {
        public string Computer { get; set; }
        public string Name { get; set; }
        public string Type { get; set; }
    }
}
