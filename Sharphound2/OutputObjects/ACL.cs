using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.OutputObjects
{
    internal class ACL
    {
        public string ObjectName { get; set; }
        public string ObjectType { get; set; }
        public string PrincipalName { get; set; }
        public string PrincipalType { get; set; }
        public string RightName { get; set; }
        public string AceType { get; set; }
        public string Qualifier { get; set; }
        public bool Inherited { get; set; }

        public string ToCSV()
        {
            return $"{ObjectName},{ObjectType},{PrincipalName},{PrincipalType},{RightName},{AceType},{Qualifier},{Inherited}";
        }

        internal object ToParam()
        {
            return new
            {
                account = ObjectName.ToUpper(),
                principal = PrincipalName.ToUpper(),
            };
        }

        internal string GetKey()
        {
            string reltype;
            switch (AceType)
            {
                case "All":
                    reltype = "AllExtendedRights";
                    break;
                case "User-Force-Change-Password":
                    reltype = "ForceChangePassword";
                    break;
                case "ExtendedRight":
                    reltype = AceType;
                    break;
                default:
                    reltype = RightName;
                    break;
            }

            reltype = reltype.Replace("-", "");

            if (reltype.Contains("WriteOwner"))
            {
                reltype = "WriteOwner";
            }

            return $"{ObjectType}|{reltype}|{PrincipalType}";
        }
    }
}
