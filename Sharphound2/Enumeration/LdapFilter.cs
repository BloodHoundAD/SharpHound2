using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Channels;

namespace Sharphound2.Enumeration
{
    internal class LdapFilter
    {

        internal static LdapData BuildLdapData(ResolvedCollectionMethod methods, bool excludeDc, string ldapFilter)
        {
            var filterparts = new List<string>();
            var props = new List<string> {"objectsid","distiguishedname"};
            if ((methods & ResolvedCollectionMethod.Group) != 0)
            {
                filterparts.Add("(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913)(primarygroupid=*))");
                props.AddRange(new[]
                {
                    "samaccountname", "distinguishedname", "samaccounttype", "member", "cn", "primarygroupid", "dnshostname"
                });
            }

            if ((methods & ResolvedCollectionMethod.LocalAdmin) != 0 ||
                (methods & ResolvedCollectionMethod.Session) != 0 ||
                (methods & ResolvedCollectionMethod.LoggedOn) != 0 || 
                (methods & ResolvedCollectionMethod.RDP) != 0 || 
                (methods & ResolvedCollectionMethod.SessionLoop) != 0 ||
                (methods & ResolvedCollectionMethod.DCOM) != 0)
            {
                filterparts.Add("(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))");
                props.AddRange(new[]
                {
                    "samaccountname", "distinguishedname", "dnshostname", "samaccounttype"
                });
            }

            if ((methods & ResolvedCollectionMethod.Trusts) != 0)
            {
                filterparts.Add("(objectclass=domain)");
                props.AddRange(new[]
                {
                    "distinguishedname"
                });
            }

            if ((methods & ResolvedCollectionMethod.ACL) != 0)
            {
                filterparts.Add("(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectClass=domain)(objectCategory=groupPolicyContainer))");
                props.AddRange(new[]
                {
                    "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "ntsecuritydescriptor", "displayname", "objectclass", "objectsid", "name"
                });
            }

            if ((methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                filterparts.Add("(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913)(samaccounttype=805306368)(samaccounttype=805306369)(objectclass=domain)(objectclass=organizationalUnit)(objectcategory=groupPolicyContainer))");
                props.AddRange(new[]
                {
                    "samaccountname", "distinguishedname", "samaccounttype", "pwdlastset", "lastlogon", "lastlogontimestamp", "objectsid",
                    "sidhistory", "useraccountcontrol", "dnshostname", "operatingsystem",
                    "operatingsystemservicepack", "serviceprincipalname", "displayname", "mail", "title",
                    "homedirectory","description","admincount","userpassword","gpcfilesyspath","objectclass",
                    "msds-behavior-version","objectguid", "name", "gpoptions", "msds-allowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity"
                });
            }

            if ((methods & ResolvedCollectionMethod.GPOLocalGroup) != 0)
            {
                filterparts.Add("(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))");
                props.AddRange(new[]
                {
                    "displayname", "name", "gpcfilesyspath", "objectclass"
                });
            }

            if ((methods & ResolvedCollectionMethod.Container) != 0)
            {
                filterparts.Add("(|(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))(objectcategory=organizationalUnit)(objectClass=domain))");
                props.AddRange(new[]
                {
                    "displayname", "name", "objectguid", "gplink", "gpoptions", "objectclass"
                });
            }

            if ((methods & ResolvedCollectionMethod.SPNTargets) != 0)
            {
                filterparts.Add("(|(&(samaccounttype=805306368)(serviceprincipalname=*)))");
                props.AddRange(new[]
                {
                    "serviceprincipalname", "samaccountname", "samaccounttype"
                });
            }


            var filter = string.Join("", filterparts.ToArray());
            filter = filterparts.Count == 1 ? filterparts[0] : $"(|{filter})";

            if (excludeDc)
            {
                filter = $"(&({filter})(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))";
            }

            if (ldapFilter != null)
            {
                filter = $"(&({filter})({ldapFilter}))";
            }

            props.Add("ms-mcs-admpwdexpirationtime");

            return new LdapData
            {
                Filter = filter,
                Properties = props.Distinct().ToArray()
            };
        }
    }

    internal class LdapData
    {
        public string Filter { get; set; }
        public string[] Properties { get; set; }
    }
}
