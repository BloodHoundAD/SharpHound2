using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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
        
        public override string ToCsv()
        {
            return
                $"{ContainerType},{ContainerName},{ContainerGuid},{ContainerBlocksInheritance},{ObjectType},{ObjectName}";
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
