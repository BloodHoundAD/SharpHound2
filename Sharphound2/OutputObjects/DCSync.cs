using System.Collections.Generic;

namespace Sharphound2.OutputObjects
{
    internal class DcSync
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

        public List<ACL> GetAcls()
        {
            var t = new List<ACL>();
            if (GetChanges && GetChangesAll)
            {
                t.Add(new ACL
                {
                    AceType = "DCSync",
                    Inherited = false,
                    ObjectName = Domain,
                    ObjectType = "domain",
                    PrincipalName = PrincipalName,
                    PrincipalType = PrincipalType,
                    Qualifier = "",
                    RightName = "ExtendedRight"
                });
            }

            if (GetChanges)
            {
                t.Add(new ACL
                {
                    AceType = "GetChanges",
                    Inherited = false,
                    ObjectName = Domain,
                    ObjectType = "domain",
                    PrincipalName = PrincipalName,
                    PrincipalType = PrincipalType,
                    Qualifier = "",
                    RightName = "ExtendedRight"
                });
            }

            if (GetChangesAll)
            {
                t.Add(new ACL
                {
                    AceType = "GetChangesAll",
                    Inherited = false,
                    ObjectName = Domain,
                    ObjectType = "domain",
                    PrincipalName = PrincipalName,
                    PrincipalType = PrincipalType,
                    Qualifier = "",
                    RightName = "ExtendedRight"
                });
            }

            return t;
        }

        public ACL GetOutputObj()
        {
            return new ACL
            {
                AceType = "DCSync",
                Inherited = false,
                ObjectName = Domain,
                ObjectType = "domain",
                PrincipalName = PrincipalName,
                PrincipalType = PrincipalType,
                Qualifier = "",
                RightName = "ExtendedRight"
            };
        }

        public ACL GetPartialObj()
        {
            if (GetChanges)
            {
                return new ACL
                {
                    AceType = "GetChanges",
                    Inherited = false,
                    ObjectName = Domain,
                    ObjectType = "domain",
                    PrincipalName = PrincipalName,
                    PrincipalType = PrincipalType,
                    Qualifier = "",
                    RightName = "ExtendedRight"
                };
            }
            return new ACL
            {
                AceType = "GetChangesAll",
                Inherited = false,
                ObjectName = Domain,
                ObjectType = "domain",
                PrincipalName = PrincipalName,
                PrincipalType = PrincipalType,
                Qualifier = "",
                RightName = "ExtendedRight"
            };
        }
    }
}
