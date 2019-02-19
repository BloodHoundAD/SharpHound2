using System.Collections.Generic;

namespace Sharphound2.JsonObjects
{
    internal class Ou : JsonBase
    {
        public string Guid { get; set; }

        public Dictionary<string, object> Properties = new Dictionary<string, object>();

        public string[] ChildOus { get; set; }
        public string[] Computers { get; set; }
        public string[] Users { get; set; }
        public GpLink[] Links { get; set; }
        public ACL[] Aces { get; set; }
    }
}
