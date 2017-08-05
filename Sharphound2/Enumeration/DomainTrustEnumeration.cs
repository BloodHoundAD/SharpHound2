using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Text;
using Sharphound2.OutputObjects;

namespace Sharphound2.Enumeration
{
    internal static class DomainTrustEnumeration
    {
        private static Utils _utils;

        public static void Init()
        {
            _utils = Utils.Instance;
        }

        public static void DoTrustEnumeration(string domain)
        {
            var complete = new List<string>();
            var queue = new Stack<string>();

            queue.Push(_utils.GetDomain(domain).Name);

            var stream = new StreamWriter("trusts.csv");
            var append = File.Exists("trusts.csv");

            if (!append)
                stream.WriteLine("SourceDomain,TargetDomain,TrustDirection,TrustType,Transitive");

            while (queue.Count > 0)
            {
                var current = queue.Pop();

                if (current == null || current.Trim() == "" || complete.Contains(current))
                {
                    continue;
                }

                Console.WriteLine($"Enumerating trusts for {current}");
                complete.Add(current);

                using (var conn = _utils.GetLdapConnection(current))
                {
                    var request = _utils.GetSearchRequest("(objectclass=trustedDomain)", SearchScope.Subtree, null,
                        current);

                    var response = (SearchResponse)conn.SendRequest(request);
                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        var properties = entry.Attributes;
                        var tAttribs = int.Parse(properties["trustattributes"][0].ToString());
                        string trustDirection;
                        switch (properties["trustdirection"][0])
                        {
                            case 0:
                                trustDirection = "Disabled";
                                break;
                            case 1:
                                trustDirection = "Inbound";
                                break;
                            case 2:
                                trustDirection = "Outbound";
                                break;
                            case 3:
                                trustDirection = "Bidirectional";
                                break;
                            default:
                                trustDirection = null;
                                break;
                        }

                        if ((tAttribs & 0x4) == 0x4)
                        {
                            Console.WriteLine("Quarantined");
                        }
                    }
                }
            }
        }

        [Flags]
        private enum TrustAttributes
        {
            NonTransitive = 0x1,
            UplevelOnly = 0x2,
            Quarantined = 0x4,
            ForestTransitive = 0x8,
            CrossOrganization = 0x10,
            WithinForest = 0x20,
            TreatAsExternal = 0x40,
            UsesRc4 = 0x80,
            UsesAes = 0x100,
            CrossOrganizationNoTgt = 0x200,
            PimTrust = 0x400
        }
    }
}
