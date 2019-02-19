using System;

namespace Sharphound2.JsonObjects
{
    internal class ACL : IEquatable<ACL>
    {
        public string PrincipalName { get; set; }
        public string PrincipalType { get; set; }
        public string RightName { get; set; }

        public string AceType { get; set; }
        //public string Qualifier { get; set; }
        //public bool Inherited { get; set; }

        public bool Equals(ACL other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(PrincipalName, other.PrincipalName) &&
                   string.Equals(PrincipalType, other.PrincipalType) && string.Equals(RightName, other.RightName) &&
                   string.Equals(AceType, other.AceType);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((ACL) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = PrincipalName != null ? PrincipalName.GetHashCode() : 0;
                hashCode = (hashCode * 397) ^ (PrincipalType != null ? PrincipalType.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (RightName != null ? RightName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (AceType != null ? AceType.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}