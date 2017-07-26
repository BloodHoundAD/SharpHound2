using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.OutputObjects
{
    internal class LocalAdmin : OutputBase
    {
        public string Server { get; set; }
        public string ObjectName { get; set; }
        public string ObjectType { get; set; }

        public override object ToParam()
        {
            return new
            {
                account = ObjectName.ToUpper(),
                computer = Server.ToUpper()
            };
        }

        public override string ToCsv()
        {
            return $"{Server.ToUpper()},{ObjectName.ToUpper()},{ObjectType.ToLower()}";
        }
    }
}
