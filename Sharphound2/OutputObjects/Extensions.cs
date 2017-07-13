using System;
using System.Collections.Generic;
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
            string AccountType = result.GetProp("samaccounttype");

            if (groups.Contains(AccountType))
            {
                return "group";
            }
            
            if (users.Contains(AccountType))
            {
                return "user";
            }

            if (computers.Contains(AccountType))
            {
                return "computer";
            }

            //???
            return null;
        }

        public static string ResolveBloodhoundDisplay(this SearchResultEntry result)
        {
            string AccountName = result.GetProp("samaccountname");
            string DistinguishedName = result.DistinguishedName;
            string AccountType = result.GetProp("samaccounttype");

            if (AccountName == null || AccountType == null || DistinguishedName == null)
            {
                return null;
            }

            string Domain = Utils.ConvertDNToDomain(DistinguishedName);

            if (groups.Contains(AccountType) || users.Contains(AccountType))
            {
                return $"{AccountName.ToUpper()}@{Domain}";
            }

            if (computers.Contains(AccountType))
            {
                string DNSHostName = result.GetProp("dnshostname");
                string[] spns;
                if (DNSHostName == null && (spns = result.GetPropArray("serviceprincipalname")) != null)
                {
                    foreach (string s in spns)
                    {
                        var x = SPNSearch.Match(s);
                        if (x.Success)
                        {
                            DNSHostName = x.Groups[1].Value;
                            break;
                        }
                    }
                }

                return DNSHostName.ToUpper();
            }

            //If we got here, something is horribly wrong
            return null;
        }

        public static string GetProp(this SearchResultEntry result, string prop)
        {
            if (!result.Attributes.Contains(prop))
            {
                return null;
            }

            return result.Attributes[prop][0].ToString();
        }

        public static string[] GetPropArray(this SearchResultEntry result, string prop)
        {
            if (!result.Attributes.Contains(prop))
            {
                return new string[0];
            }

            var values = result.Attributes[prop];

            string[] toreturn = new string[result.Attributes[prop].Count];
            for (int i = 0; i < values.Count; i++)
            {
                toreturn[i] = values[i].ToString();
            }

            return toreturn;
        }

        public static string Sid(this SearchResultEntry result)
        {
            if (!result.Attributes.Contains("objectsid"))
            {
                return null;
            }

            return new SecurityIdentifier(result.Attributes["objectsid"][0] as byte[], 0).ToString();
        }

    }
}
