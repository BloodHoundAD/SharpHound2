using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class Trust
    {
        public string TargetName { get; set; }
        public bool? IsTransitive { get; set; }
        public string TrustDirection { get; set; }
        public string TrustType { get; set; }
    }
}
