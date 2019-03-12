using System.Collections.Generic;

namespace Sharphound2.JsonObjects
{
    internal class Computer : JsonBase
    {
        private string _name;
        public string Name
        {
            get => _name;
            set => _name = value.ToUpper();
        }
        public string PrimaryGroup { get; set; }

        public Dictionary<string, object> Properties = new Dictionary<string, object>();

        public LocalMember[] LocalAdmins { get; set; }
        public LocalMember[] RemoteDesktopUsers { get; set; }
        public LocalMember[] DcomUsers { get; set; }
        public string[] AllowedToDelegate { get; set; }
        public LocalMember[] AllowedToAct { get; set; }
        public ACL[] Aces { get; set; }
    }
}
