using System.Collections.Generic;

namespace Sharphound2.JsonObjects
{
    internal class Computer : JsonBase
    {
        public string Name { get; set; }
        public string PrimaryGroup { get; set; }

        public Dictionary<string, object> Properties = new Dictionary<string, object>();

        public LocalMember[] LocalAdmins { get; set; }
        public LocalMember[] RemoteDesktopUsers { get; set; }
        public LocalMember[] DcomUsers { get; set; }
    }
}
