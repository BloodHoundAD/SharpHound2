using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Text;

namespace Sharphound2.Enumeration
{
    internal class DomainTrustEnumeration
    {
        private readonly Utils _utils;
        public DomainTrustEnumeration()
        {
            _utils = Utils.Instance;
        }

        public void DoTrustEnumeration()
        {
            var complete = new List<string>();
            var queue = new Stack<string>();

            queue.Push(_utils.GetDomain().Name);

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


                    }
                }
            }
        }
    }
}
