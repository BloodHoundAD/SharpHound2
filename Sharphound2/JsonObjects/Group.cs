using System.Collections.Generic;

namespace Sharphound2.JsonObjects
{
    internal class Group : JsonBase
    {
        private string _name;
        public string Name
        {
            get => _name;
            set => _name = value.ToUpper();
        }

        public Dictionary<string, object> Properties = new Dictionary<string, object>();
        
        public ACL[] Aces { get; set; }
        public GroupMember[] Members { get; set; }
    }
}
