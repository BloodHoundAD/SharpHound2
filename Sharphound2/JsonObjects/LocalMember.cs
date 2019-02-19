using System;

namespace Sharphound2.JsonObjects
{
    internal class LocalMember : IEquatable<LocalMember>
    {
        private string _type;

        public string Name { get; set; }

        public string Type
        {
            get => _type;
            set => _type = value.ToTitleCase();
        }

        public bool Equals(LocalMember other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(_type, other._type) && string.Equals(Name, other.Name);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((LocalMember) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((_type != null ? _type.GetHashCode() : 0) * 397) ^ (Name != null ? Name.GetHashCode() : 0);
            }
        }
    }
}