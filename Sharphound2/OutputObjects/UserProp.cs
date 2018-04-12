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
        internal string Domain { get; set; }

        public override string ToCsv()
        {
            return $"{AccountName},{Utils.StringToCsvCell(DisplayName)},{Enabled},{PwdLastSet},{LastLogon},{ObjectSid},{SidHistory},{HasSpn},{Utils.StringToCsvCell(ServicePrincipalNames)},{Utils.StringToCsvCell(Email)},{Domain}";
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
                ServicePrincipalNames = spn,
                Domain
            };
        }

        public override string TypeHash()
        {
            return "a|UserProp|b";
        }
    }
}
