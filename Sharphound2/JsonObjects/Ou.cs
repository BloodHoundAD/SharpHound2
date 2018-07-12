using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class Ou : JsonBase
    {
        public string Name { get; set; }
        public string Guid { get; set; }
        public bool? BlocksInheritance { get; set; }

        public string[] ChildOus { get; set; }
        public string[] Computers { get; set; }
        public string[] Users { get; set; }
        public GpLink[] Links { get; set; }
    }
}
