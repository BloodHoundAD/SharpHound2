using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Sharphound2.Enumeration;

namespace Sharphound2
{
    public static class Extensions
    {
        private static readonly HashSet<string> Groups = new HashSet<string> { "268435456", "268435457", "536870912", "536870913" };
        private static readonly HashSet<string> Computers = new HashSet<string> { "805306369" };
        private static readonly HashSet<string> Users = new HashSet<string> { "805306368" };
        private static readonly HashSet<string> TrustAccount = new HashSet<string> { "805306370" };
        //private static readonly Regex SpnSearch = new Regex(@"HOST\/([A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*)$", RegexOptions.Compiled);
        private static string _primaryDomain;

        static Extensions()
        {
        }

        public static void Init()
        {
            _primaryDomain = Utils.Instance.GetDomain().Name;
        }

        public static string GetObjectType(this SearchResultEntry result)
        {
            var accountType = result.GetProp("samaccounttype");

            if (Groups.Contains(accountType))
            {
                return "group";
            }
            
            if (Users.Contains(accountType))
            {
                return "user";
            }

            if (Computers.Contains(accountType))
            {
                return "computer";
            }

            if (TrustAccount.Contains(accountType))
            {
                return "trustaccount";
            }

            if (result.DistinguishedName.Contains("ForeignSecurityPrincipals"))
            {
                return "foreignsecurityprincipal";
            }

            return "domain";
        }

        internal static ResolvedEntry ResolveAdEntry(this SearchResultEntry result)
        {
            var entry = new ResolvedEntry();

            var accountName = result.GetProp("samaccountname");
            var distinguishedName = result.DistinguishedName;
            var accountType = result.GetProp("samaccounttype");

            if (distinguishedName == null)
                return null;

            var domainName = Utils.ConvertDnToDomain(distinguishedName);

            if (Groups.Contains(accountType))
            {
                entry.BloodHoundDisplay = $"{accountName}@{domainName}".ToUpper();
                entry.ObjectType = "group";
                return entry;
            }

            if (Users.Contains(accountType))
            {
                entry.BloodHoundDisplay = $"{accountName}@{domainName}".ToUpper();
                entry.ObjectType = "user";
                return entry;
            }

            if (Computers.Contains(accountType))
            {
                var shortName = accountName?.TrimEnd('$');
                var dnshostname = result.GetProp("dnshostname");
                
                if (dnshostname == null)
                {
                    bool hostFound;
                    if (domainName.Equals(_primaryDomain, StringComparison.CurrentCultureIgnoreCase))
                    {
                        hostFound = DnsManager.HostExistsDns(shortName, out dnshostname);
                        if (!hostFound)
                            hostFound = DnsManager.HostExistsDns($"{shortName}.{domainName}", out dnshostname);
                    }
                    else
                    {
                        hostFound = DnsManager.HostExistsDns($"{shortName}.{domainName}", out dnshostname);
                        if (!hostFound)
                            hostFound = DnsManager.HostExistsDns(shortName, out dnshostname);
                    }

                    if (!hostFound)
                        return null;
                    
                }
                entry.BloodHoundDisplay = dnshostname;
                entry.ObjectType = "computer";
                entry.ComputerSamAccountName = shortName;
                return entry;
            }

            entry.BloodHoundDisplay = domainName;
            entry.ObjectType = "domain";
            return entry;
        }

        public static string ResolveBloodhoundDisplay(this SearchResultEntry result)
        {
            var accountName = result.GetProp("samaccountname");
            var distinguishedName = result.DistinguishedName;
            var accountType = result.GetProp("samaccounttype");

            //I have no idea if this is a thing
            if (distinguishedName == null)
                return null;

            var domain = Utils.ConvertDnToDomain(distinguishedName);

            if (Groups.Contains(accountType) || Users.Contains(accountType))
            {
                return $"{accountName.ToUpper()}@{domain}";
            }

            if (Computers.Contains(accountType))
            {
                var dnsHostName = result.GetProp("dnshostname") ?? $"{accountName.TrimEnd('$')}.{domain}";
                
                return dnsHostName.ToUpper();
            }
            
            //If we got here, we have a domain ACL object
            return Utils.ConvertDnToDomain(distinguishedName);
        }

        public static string GetProp(this SearchResultEntry result, string prop)
        {
            if (!result.Attributes.Contains(prop))
                return null;

            return result.Attributes[prop][0].ToString();
        }

        public static byte[] GetPropBytes(this SearchResultEntry result, string prop)
        {
            if (!result.Attributes.Contains(prop))
                return null;

            return result.Attributes[prop][0] as byte[];
        }

        public static byte[] GetSid(this DirectoryEntry result)
        {
            return result.Properties["objectsid"][0] as byte[];
        }

        public static string[] GetPropArray(this SearchResultEntry result, string prop)
        {
            if (!result.Attributes.Contains(prop))
                return new string[0];

            var values = result.Attributes[prop];

            var toreturn = new string[values.Count];
            for (var i = 0; i < values.Count; i++)
                toreturn[i] = values[i].ToString();

            return toreturn;
        }

        
        public static string GetSid(this SearchResultEntry result)
        {
            if (!result.Attributes.Contains("objectsid"))
                return null;

            return new SecurityIdentifier(result.Attributes["objectsid"][0] as byte[], 0).ToString();
        }
    }
}
