using System.Collections.Generic;

namespace Sharphound2.JsonObjects
{
    internal class User : JsonBase
    {
        private string _name;
        public string Name
        {
            get => _name;
            set => _name = value.ToUpper();
        }
        public string PrimaryGroup { get; set; }

        public Dictionary<string, object> Properties = new Dictionary<string, object>();
        
        public ACL[] Aces { get; set; }
        public string[] AllowedToDelegate { get; set; }
        public SPNTarget[] SPNTargets { get; set; }
    }
}
