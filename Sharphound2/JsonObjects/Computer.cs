using System.Collections.Generic;

namespace Sharphound2.JsonObjects
{
    internal class Computer : JsonBase
    {
        private string _Name;
        public string Name
        {
            get => _Name;
            set => _Name = value.ToUpper();
        }
        public string PrimaryGroup { get; set; }

        public Dictionary<string, object> Properties = new Dictionary<string, object>();

        public LocalMember[] LocalAdmins { get; set; }
        public LocalMember[] RemoteDesktopUsers { get; set; }
        public LocalMember[] DcomUsers { get; set; }
        public string[] AllowedToDelegate { get; set; }
        public ACL[] Aces { get; set; }
    }
}
