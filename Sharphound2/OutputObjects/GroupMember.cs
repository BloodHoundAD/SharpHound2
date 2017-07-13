using System;

namespace Sharphound2.OutputObjects
{
    class GroupMember
    {
        public string GroupName { get; set; }
        public string AccountName { get; set; }
        public string ObjectType { get; set; }

        public string ToCSV()
        {
            return String.Format("{0},{1},{2}", GroupName.ToUpper(), AccountName.ToUpper(), ObjectType.ToLower());
        }

        internal object ToParam()
        {
            return new
            {
                account = AccountName.ToUpper(),
                group = GroupName.ToUpper()
            };
        }
    }
}
