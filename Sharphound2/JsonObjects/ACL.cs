using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class ACL
    {
        public string PrincipalName { get; set; }
        public string PrincipalType { get; set; }
        public string RightName { get; set; }
        public string AceType { get; set; }
        public string Qualifier { get; set; }
        public bool Inherited { get; set; }
    }
}
