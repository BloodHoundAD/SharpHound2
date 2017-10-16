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
        internal string DisplayName { get; set; }
        internal string Email { get; set; }

        public override string ToCsv()
        {
            return $"{AccountName},{StringToCsvCell(DisplayName)},{Enabled},{PwdLastSet},{LastLogon},{ObjectSid},{SidHistory},{HasSpn},{StringToCsvCell(ServicePrincipalNames)},{StringToCsvCell(Email)}";
        }

        public override object ToParam()
        {
            var spn = ServicePrincipalNames.Split('|');
            return new
            {
                AccountName,
                DisplayName,
                Enabled,
                PwdLastSet,
                LastLogon,
                ObjectSid,
                SidHistory,
                HasSpn,
                Email,
                ServicePrincipalNames = spn
            };
        }

        public override string TypeHash()
        {
            return "a|UserProp|b";
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
