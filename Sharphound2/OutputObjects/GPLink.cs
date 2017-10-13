using System;

namespace Sharphound2.OutputObjects
{
    internal class GpLink : OutputBase
    {
        internal string ObjectType { get; set; }
        internal string ObjectName { get; set; }
        internal string ObjectGuid { get; set; }
        internal string GpoDisplayName { get; set; }
        internal string GpoGuid { get; set; }
        internal bool IsEnforced { get; set; }

        public override string ToCsv()
        {
            return $"{ObjectType},{ObjectName},{ObjectGuid},{GpoDisplayName},{GpoGuid},{IsEnforced}";
        }

        public override object ToParam()
        {
            throw new NotImplementedException();
        }

        public override string TypeHash()
        {
            throw new NotImplementedException();
        }
    }
}
