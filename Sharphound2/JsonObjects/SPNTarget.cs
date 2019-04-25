using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    class SPNTarget : IEquatable<SPNTarget>
    {
        private string _computerName;

        public string ComputerName
        {
            get => _computerName;
            set => _computerName = value.ToUpper();
        }

        public int Port { get; set; }

        public string Service { get; set; }

        public bool Equals(SPNTarget other)
        {
            return string.Equals(_computerName, other._computerName) && string.Equals(Service, other.Service) && Port == other.Port;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((SPNTarget) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = (_computerName != null ? _computerName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (Service != null ? Service.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ Port;
                return hashCode;
            }
        }
    }
}
