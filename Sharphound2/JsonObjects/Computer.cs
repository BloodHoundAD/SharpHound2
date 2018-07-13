using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class Computer : JsonBase
    {
        public string Name { get; set; }
        public string PrimaryGroup { get; set; }

        public Dictionary<string, object> properties = new Dictionary<string, object>();

        public LocalMember[] LocalAdmins { get; set; }
        public LocalMember[] RemoteDesktopUsers { get; set; }
    }
}
