using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.OutputObjects
{
    internal class ComputerProp : OutputBase
    {
        internal string ComputerName { get; set; }
        internal bool Enabled { get; set; }
        internal long PwdLastSet { get; set; }
        internal long LastLogon { get; set; }
        internal string ObjectSid { get; set; }
        internal string OperatingSystem { get; set; }
        internal bool UnconstrainedDelegation { get; set; }

        public override string ToCsv()
        {
            return $"{ComputerName},{Enabled},{UnconstrainedDelegation},{PwdLastSet},{LastLogon},{OperatingSystem},{ObjectSid}";
        }

        public override object ToParam()
        {
            return new
            {
                ComputerName,
                Enabled,
                UnconstrainedDelegation,
                PwdLastSet,
                LastLogon,
                OperatingSystem,
                ObjectSid
            };
        }

        public override string TypeHash()
        {
            return "a|CompProp|b";
        }
    }
}
