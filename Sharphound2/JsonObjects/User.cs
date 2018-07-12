using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class User : JsonBase
    {
        public string Name { get; set; }
        public string ObjectSid { get; set; }
        public string DisplayName { get;set; }
        public bool? AdminCount { get; set; }
        public long? PwdLastSet { get; set; }
        public long? LastLogon { get; set; }
        public bool? Enabled { get; set; }
        public string SidHistory { get; set; }
        public bool? HasSpn { get; set; }
        public string[] ServicePrincipalNames { get; set; }
        public string Email { get; set; }
        public string Domain { get; set; }
        public string Title { get; set; }
        public string HomeDirectory { get; set; }
        public string Description { get; set; }
        public string UserPassword { get; set; }
        public string PrimaryGroup { get; set; }

        //Inbound Aces
        public ACL[] Aces { get; set; }
    }
}
