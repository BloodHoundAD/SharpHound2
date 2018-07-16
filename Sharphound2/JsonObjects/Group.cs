using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class Group : JsonBase
    {
        public string Name { get; set; }

        public Dictionary<string, object> Properties = new Dictionary<string, object>();
        
        public ACL[] Aces { get; set; }
        public GroupMember[] Members { get; set; }
    }
}
