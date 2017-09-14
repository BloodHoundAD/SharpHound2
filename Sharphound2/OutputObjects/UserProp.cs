using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.OutputObjects
{
    internal class UserProp : OutputBase
    {
        internal string AccountName { get; set; }
        internal bool Enabled { get; set; }
        internal long PwdLastSet { get; set; }
        internal long LastLogon { get; set; }
        internal string ObjectSid { get; set; }
        internal string SidHistory { get; set; }
        internal bool HasSpn { get; set; }
        internal string ServicePrincipalNames { get; set; }

        public override string ToCsv()
        {
            return $"{AccountName},{Enabled},{PwdLastSet},{LastLogon},{ObjectSid},{SidHistory},{HasSpn},{ServicePrincipalNames}";
        }

        public override object ToParam()
        {
            throw new NotImplementedException();
        }

        public override string TypeHash()
        {
            return "userprop";
        }
    }
}
