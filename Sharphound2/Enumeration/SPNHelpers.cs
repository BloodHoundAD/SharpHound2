using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using Sharphound2.JsonObjects;

namespace Sharphound2.Enumeration
{
    internal static class SPNHelpers
    {
        private static Utils _utils;

        internal static void GetSpnTargets(SearchResultEntry entry, ResolvedEntry resolved, ref User obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.SPNTargets))
            {
                return;
            }

            var spn = entry.GetPropArray("serviceprincipalname");
            var resolvedTargets = new List<SPNTarget>();
            var domain = Utils.ConvertDnToDomain(entry.DistinguishedName);
            foreach (var sp in spn)
            {
                if (sp.Contains("@"))
                    continue;

                if (sp.ToLower().Contains("mssqlsvc"))
                {
                    var initial = sp.Split('/')[1];
                    string host;
                    int port;
                    if (initial.Contains(':'))
                    {
                        var t = initial.Split(':');
                        host = t[0];
                        if (!int.TryParse(t[1], out port))
                        {
                            port = 1433;
                        }
                    }
                    else
                    {
                        host = initial;
                        port = 1433;
                    }

                    var resolvedHost = Utils.Instance.ResolveHost(host, domain);
                    if (!resolvedHost.Contains(".")) continue;
                    
                    if (Utils.CheckSqlServer(resolvedHost, port))
                    {
                        resolvedTargets.Add(new SPNTarget
                        {
                            ComputerName =  resolvedHost,
                            Port = port,
                            Service = "SQLAdmin"
                        });
                    }
                }
            }

            obj.SPNTargets = resolvedTargets.Distinct().ToArray();
        }
    }
}
