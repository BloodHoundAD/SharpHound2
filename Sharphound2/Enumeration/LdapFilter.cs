using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.Enumeration
{
    internal class LdapFilter
    {
        public static LdapData GetLdapFilter(CollectionMethod method, bool excludeDc, bool stealth)
        {
            string ldapFilter;
            string[] props;
            switch (method)
            {
                case CollectionMethod.Container:
                    ldapFilter = "";
                    props = new string[] { };
                    break;
                case CollectionMethod.Group:
                    ldapFilter = "(|(memberof=*)(primarygroupid=*))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid",
                        "memberof"
                    };
                    break;
                case CollectionMethod.ComputerOnly:
                    if (stealth)
                    {
                        ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                        props = new[]
                        {
                            "samaccountname", "distinguishedname", "dnshostname", "samaccounttype"
                        };
                    }
                    else
                    {
                        ldapFilter = "(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))";
                        props = new[] {"displayname", "name", "gpcfilesyspath"};
                    }
                    break;
                case CollectionMethod.LocalGroup:
                    ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype"
                    };
                    break;
                case CollectionMethod.GPOLocalGroup:
                    ldapFilter = "(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))";
                    props = new[]
                    {
                        "displayname", "name", "gpcfilesyspath"
                    };
                    break;
                case CollectionMethod.Session:
                    ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                    if (excludeDc)
                    {
                        ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))";
                    }
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype"
                    };
                    break;
                case CollectionMethod.LoggedOn:
                    ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype"
                    };
                    break;
                case CollectionMethod.Trusts:
                    ldapFilter = "(objectclass=domain)";
                    props = new[]
                    {
                        "distinguishedname"
                    };
                    break;
                case CollectionMethod.ACL:
                    ldapFilter =
                        "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectClass=domain))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "ntsecuritydescriptor"
                    };
                    break;
                case CollectionMethod.SessionLoop:
                    ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                    if (excludeDc)
                    {
                        ldapFilter = "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))";
                    }
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype"
                    };
                    break;
                case CollectionMethod.Default:
                    ldapFilter = "(|(memberof=*)(primarygroupid=*)(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid",
                        "memberof"
                    };
                    break;
                case CollectionMethod.ObjectProps:
                    ldapFilter = "(|(samaccounttype=805306368)(samaccounttype=805306369))";
                    props = new[]
                    {
                        "samaccountname", "distinguishedname", "samaccounttype", "pwdlastset", "lastlogon", "objectsid",
                        "sidhistory", "useraccountcontrol", "dnshostname", "operatingsystem",
                        "operatingsystemservicepack", "serviceprincipalname"
                    };
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(method), method, null);
            }
            return new LdapData
            {
                Filter = ldapFilter,
                Properties = props
            };
        }
    }

    internal class LdapData
    {
        public string Filter { get; set; }
        public string[] Properties { get; set; }
    }
}
