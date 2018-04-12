using System;

namespace Sharphound2.OutputObjects
{
    internal class Container : OutputBase
    {
        internal string ContainerType { get; set; }
        internal string ContainerName { get; set; }
        internal string ContainerGuid { get; set; }
        internal bool ContainerBlocksInheritance { get; set; }
        internal string ObjectType { get; set; }
        internal string ObjectName { get; set; }
        internal string ObjectId { get; set; }
        
        public override string ToCsv()
        {
            return
                $"{ContainerType},{Utils.StringToCsvCell(ContainerName)},{ContainerGuid},{ContainerBlocksInheritance},{ObjectType},{Utils.StringToCsvCell(ObjectName)},{ObjectId}";
        }

        public override object ToParam()
        {
            throw new NotImplementedException();
        }

        public override string TypeHash()
        {
            return $"{ContainerType}|Structure|{ObjectType}";
        }
    }
}
