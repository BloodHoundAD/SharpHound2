using System.Collections.Generic;

namespace Sharphound2.JsonObjects
{
    internal class User : JsonBase
    {
        public string Name { get; set; }
        public string PrimaryGroup { get; set; }

        public Dictionary<string, object> Properties = new Dictionary<string, object>();
        
        public ACL[] Aces { get; set; }
        public string[] AllowedToDelegate { get; set; }
    }
}
