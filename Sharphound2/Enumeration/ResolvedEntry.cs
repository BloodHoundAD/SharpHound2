namespace Sharphound2.Enumeration
{
    internal class ResolvedEntry
    {
        private string _displayName;
        private string _objecttype;

        public string BloodHoundDisplay
        {
            get => _displayName.ToUpper();
            set => _displayName = value;
        }
        public string ObjectType
        {
            get => _objecttype.ToLower();
            set => _objecttype = value;
        }

        public string ComputerSamAccountName { get; set; }

        public override string ToString()
        {
            return $"{BloodHoundDisplay} - {ObjectType}";
        }
    }
}
