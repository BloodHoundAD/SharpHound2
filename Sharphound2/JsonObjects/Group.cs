using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class Group : JsonBase
    {
        public string Name { get; set; }
        public string ObjectSid { get; set; }
        public string Domain { get; set; }
        public string Description { get; set; }
        public bool? AdminCount { get; set; }
        
        public ACL[] Aces { get; set; }
        public GroupMember[] Members { get; set; }
    }
}
