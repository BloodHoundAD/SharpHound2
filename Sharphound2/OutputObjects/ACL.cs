using System;
using System.Collections;
using System.Collections.Generic;

namespace Sharphound2.OutputObjects
{
    internal class ACL : OutputBase
    {
        public string ObjectName { get; set; }
        public string ObjectType { get; set; }
        public string PrincipalName { get; set; }
        public string PrincipalType { get; set; }
        public string RightName { get; set; }
        public string AceType { get; set; }
        public string Qualifier { get; set; }
        public bool Inherited { get; set; }

        public override string ToCsv()
        {
            return $"{ObjectName},{ObjectType},{PrincipalName},{PrincipalType},{RightName},{AceType},{Qualifier},{Inherited}";
        }

        public override object ToParam()
        {
            return new
            {
                a = PrincipalName.ToUpper(),
                b = ObjectName.ToUpper(),
            };
        }

        public IEnumerable<string> GetAllTypeHashes()
        {
            var right = RightName;
            var extright = AceType;

            if (extright.Equals("All"))
                yield return $"{PrincipalType}|AllExtendedRights|{ObjectType}";
            else if (extright.Equals("User-Force-Change-Password"))
                yield return $"{PrincipalType}|ForceChangePassword|{ObjectType}";
            else if (right.Equals("ExtendedRight"))
                yield return $"{PrincipalType}|{extright}|{ObjectType}";

            if (right.Contains("GenericAll"))
                yield return $"{PrincipalType}|GenericAll|{ObjectType}";

            if (right.Contains("WriteDacl"))
                yield return $"{PrincipalType}|WriteDacl|{ObjectType}";

            if (right.Contains("WriteOwner"))
                yield return $"{PrincipalType}|WriteOwner|{ObjectType}";

            if (right.Contains("GenericWrite"))
                yield return $"{PrincipalType}|GenericWrite|{ObjectType}";

            if (right.Contains("WriteProperty") && extright.Equals("Member"))
                yield return $"{PrincipalType}|AddMember|{ObjectType}";
        }

        public override string TypeHash()
        {
            throw new NotImplementedException();
        }
    }
}
