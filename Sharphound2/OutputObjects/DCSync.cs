using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.OutputObjects
{
    class DcSync
    {
        public string Domain { get; set; }
        public string PrincipalName { get; set; }
        public string PrincipalType { get; set; }
        public bool GetChanges { get; set; }
        public bool GetChangesAll { get; set; }

        public bool CanDCSync()
        {
            return GetChanges && GetChangesAll;
        }

        //public ACLInfo GetOutputObj()
        //{
        //    return new ACLInfo
        //    {
        //        AceType = "DCSync",
        //        Inherited = false,
        //        ObjectName = Domain,
        //        ObjectType = "domain",
        //        PrincipalName = PrincipalName,
        //        PrincipalType = PrincipalType,
        //        Qualifier = "",
        //        RightName = "ExtendedRight"
        //    };
        //}
    }
}
