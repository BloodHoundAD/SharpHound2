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

        public override string ToCsv()
        {
            return $"{ComputerName},{Enabled},{PwdLastSet},{LastLogon},{OperatingSystem},{ObjectSid}";
        }

        public override object ToParam()
        {
            throw new NotImplementedException();
        }

        public override string TypeHash()
        {
            throw new NotImplementedException();
        }
    }
}
