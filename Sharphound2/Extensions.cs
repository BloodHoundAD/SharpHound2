using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Sharphound2.OutputObjects
{
    public static class Extensions
    {
        static HashSet<string> groups = new HashSet<string>() { "268435456", "268435457", "536870912", "536870913" };
        static HashSet<string> computers = new HashSet<string>() { "805306369" };
        static HashSet<string> users = new HashSet<string>() { "805306368" };
        static Regex SPNSearch = new Regex(@"HOST\/([A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*)$", RegexOptions.Compiled);

        public static string GetObjectType(this SearchResultEntry result)
        {
            var accountType = result.GetProp("samaccounttype");

            if (groups.Contains(accountType))
            {
                return "group";
            }
            
            if (users.Contains(accountType))
            {
                return "user";
            }

            if (computers.Contains(accountType))
            {
                return "computer";
            }

            return "domain";
        }

        public static string ResolveBloodhoundDisplay(this SearchResultEntry result)
        {
            var accountName = result.GetProp("samaccountname");
            var distinguishedName = result.DistinguishedName;
            var accountType = result.GetProp("samaccounttype");

            if (accountName == null || distinguishedName == null)
            {
                return null;
            }

            var domain = Utils.ConvertDnToDomain(distinguishedName);

            if (groups.Contains(accountType) || users.Contains(accountType))
            {
                return $"{accountName.ToUpper()}@{domain}";
            }

            if (computers.Contains(accountType))
            {
                var DNSHostName = result.GetProp("dnshostname");
                string[] spns;
                if (DNSHostName == null && (spns = result.GetPropArray("serviceprincipalname")) != null)
                {
                    foreach (var s in spns)
                    {
                        var x = SPNSearch.Match(s);
                        if (!x.Success) continue;
                        DNSHostName = x.Groups[1].Value;
                        break;
                    }
                }
                return DNSHostName?.ToUpper();
            }
            
            //If we got here, we have a domain ACL object
            return Utils.ConvertDnToDomain(distinguishedName);
        }

        public static string GetProp(this SearchResultEntry result, string prop)
        {
            if (!result.Attributes.Contains(prop))
            {
                return null;
            }

            return result.Attributes[prop][0].ToString();
        }

        public static byte[] GetPropBytes(this SearchResultEntry result, string prop)
        {
            if (!result.Attributes.Contains(prop))
            {
                return null;
            }

            return result.Attributes[prop][0] as byte[];
        }

        public static byte[] GetSid(this DirectoryEntry result)
        {
            return result.Properties["objectsid"][0] as byte[];
        }

        public static string[] GetPropArray(this SearchResultEntry result, string prop)
        {
            if (!result.Attributes.Contains(prop))
            {
                return new string[0];
            }

            var values = result.Attributes[prop];

            var toreturn = new string[values.Count];
            for (var i = 0; i < values.Count; i++)
            {
                toreturn[i] = values[i].ToString();
            }

            return toreturn;
        }

        
        public static string GetSid(this SearchResultEntry result)
        {
            if (!result.Attributes.Contains("objectsid"))
            {
                return null;
            }

            return new SecurityIdentifier(result.Attributes["objectsid"][0] as byte[], 0).ToString();
        }
    }
}
