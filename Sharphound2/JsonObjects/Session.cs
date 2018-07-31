using System;

namespace Sharphound2.JsonObjects
{
    internal class Session : JsonBase, IEquatable<Session>
    {
        private string _computerName;
        private string _userName;

        public string UserName
        {
            get => _userName;
            set => _userName = value.ToUpper();
        }

        public string ComputerName
        {
            get => _computerName;
            set => _computerName = value.ToUpper();
        }

        public int Weight { get; set; }

        public bool Equals(Session other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(_userName, other._userName) && string.Equals(_computerName, other._computerName);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((Session) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((_userName != null ? _userName.GetHashCode() : 0) * 397) ^
                       (_computerName != null ? _computerName.GetHashCode() : 0);
            }
        }
    }
}