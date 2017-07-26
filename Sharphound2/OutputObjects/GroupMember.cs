using System;

namespace Sharphound2.OutputObjects
{
    internal class GroupMember : OutputBase
    {
        public string GroupName { get; set; }
        public string AccountName { get; set; }
        public string ObjectType { get; set; }

        public override string ToCsv()
        {
            return $"{GroupName.ToUpper()},{AccountName.ToUpper()},{ObjectType.ToLower()}";
        }

        public override object ToParam()
        {
            return new
            {
                account = AccountName.ToUpper(),
                group = GroupName.ToUpper()
            };
        }
    }
}
