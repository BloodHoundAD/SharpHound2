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
            return $"{ComputerName},{Enabled},{UnconstrainedDelegation},{PwdLastSet},{LastLogon},{StringToCsvCell(OperatingSystem)},{ObjectSid}";
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

        //Thanks to Ed Bayiates on Stack Overflow for this. https://stackoverflow.com/questions/6377454/escaping-tricky-string-to-csv-format
        private static string StringToCsvCell(string str)
        {
            var mustQuote = (str.Contains(",") || str.Contains("\"") || str.Contains("\r") || str.Contains("\n"));
            if (!mustQuote) return str;
            var sb = new StringBuilder();
            sb.Append("\"");
            foreach (var nextChar in str)
            {
                sb.Append(nextChar);
                if (nextChar == '"')
                    sb.Append("\"");
            }
            sb.Append("\"");
            return sb.ToString();
        }
    }
}
