using System.Collections.Generic;

namespace Sharphound2.JsonObjects
{
    internal class Domain : JsonBase
    {
        public string Name { get; set; }
        public Dictionary<string, object> Properties = new Dictionary<string, object>();

        public GpLink[] Links { get; set; }
        public Trust[] Trusts { get; set; }
        public ACL[] Aces { get; set; }
        public string[] ChildOus { get; set; }
        public string[] Computers { get; set; }
        public string[] Users { get; set; }
    }
}
