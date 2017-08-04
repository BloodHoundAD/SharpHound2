using System;

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

        public override bool Equals(object obj)
        {
            return Equals((LocalAdmin) obj);
        }

        protected bool Equals(LocalAdmin other)
        {
            return string.Equals(Server, other.Server) && string.Equals(ObjectName, other.ObjectName) && string.Equals(ObjectType, other.ObjectType);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = (Server != null ? Server.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (ObjectName != null ? ObjectName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (ObjectType != null ? ObjectType.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}
