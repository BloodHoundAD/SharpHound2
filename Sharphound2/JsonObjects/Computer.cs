using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class Computer : JsonBase
    {
        public string ObjectGuid { get; set; }

        public string Name { get; set; }
        public bool? Enabled { get; set; }
        public long? PwdLastSet { get; set; }
        public long? LastLogon { get; set; }
        public string ObjectSid { get; set; }
        public string OperatingSystem { get; set; }
        public bool? UnconstrainedDelegation { get; set; }
        public string Domain { get; set; }
        public string Description { get; set; }
        public string PrimaryGroup { get; set; }

        public LocalMember[] LocalAdmins { get; set; }
        public LocalMember[] RemoteDesktopUsers { get; set; }
    }
}
