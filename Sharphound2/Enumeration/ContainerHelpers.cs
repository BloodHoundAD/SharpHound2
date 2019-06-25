using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using Sharphound2.JsonObjects;

namespace Sharphound2.Enumeration
{
    internal static class ContainerHelpers
    {
        private static Utils _utils;
        private static ConcurrentDictionary<string, string> _gpoCache;

        public static void Init()
        {
            _utils = Utils.Instance;
            _gpoCache = new ConcurrentDictionary<string, string>();
        }

        internal static void BuildGpoCache(string domain)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.Container))
                return;

            var d = _utils.GetDomain(domain);
            if (d == null)
                return;

            domain = d.Name;
            foreach (var entry in _utils.DoSearch("(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))",
                SearchScope.Subtree, new[] { "displayname", "name" }, domain))
            {
                var name = entry.GetProp("name").ToUpper();
                var dName = entry.GetProp("displayname")?.ToUpper() ?? name;
                name = name.Substring(1, name.Length - 2);
                _gpoCache.TryAdd(name, dName);
            }
        }

        internal static void ResolveContainer(SearchResultEntry entry, ResolvedEntry resolved, ref Ou obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.Container))
                return;

            var domain = Utils.ConvertDnToDomain(entry.DistinguishedName);

            var opts = entry.GetProp("gpoptions");
            obj.Properties.Add("blocksinheritance", opts != null && opts.Equals("1"));

            //Resolve GPLinks on the ou
            var links = new List<GpLink>();

            var gpLinks = entry.GetProp("gplink");
            if (gpLinks != null)
            {
                foreach (var l in gpLinks.Split(']', '[').Where(x => x.StartsWith("LDAP")))
                {
                    var split = l.Split(';');
                    var dn = split[0];
                    var status = split[1];
                    if (status.Equals("3") || status.Equals("1"))
                        continue;

                    var enforced = status.Equals("2");
                    var index = dn.IndexOf("CN=", StringComparison.OrdinalIgnoreCase) + 4;
                    var name = dn.Substring(index, index + 25).ToUpper();

                    if (!_gpoCache.ContainsKey(name)) continue;

                    var dName = _gpoCache[name];
                    links.Add(new GpLink
                    {
                        IsEnforced = enforced,
                        Name = $"{dName}@{domain}"
                    });
                }

                obj.Links = links.ToArray();
            }

            var computers = new List<string>();
            var users = new List<string>();
            var ous = new List<string>();
            foreach (var subEntry in _utils.DoSearch(
                "(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))",
                SearchScope.OneLevel,
                new[]
                {
                    "samaccountname", "name", "objectguid", "objectclass", "objectsid", "samaccounttype", "dnshostname"
                }, domain, entry.DistinguishedName))
            {


                var subResolved = subEntry.ResolveAdEntry();

                if (subResolved == null)
                    continue;

                if (subResolved.ObjectType.Equals("ou"))
                {
                    ous.Add(new Guid(subEntry.GetPropBytes("objectguid")).ToString().ToUpper());
                }
                else if (subResolved.ObjectType.Equals("computer"))
                {
                    computers.Add(subResolved.BloodHoundDisplay);
                }
                else
                {
                    users.Add(subResolved.BloodHoundDisplay);
                }
            }

            obj.Users = users.ToArray();

            obj.Computers = computers.ToArray();

            obj.ChildOus = ous.ToArray();
        }

        internal static void ResolveContainer(SearchResultEntry entry, ResolvedEntry resolved, ref Domain obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.Container))
                return;

            var domain = Utils.ConvertDnToDomain(entry.DistinguishedName);

            //Resolve GPLinks on the domain
            var links = new List<GpLink>();

            var gpLinks = entry.GetProp("gplink");
            if (gpLinks != null)
            {
                foreach (var l in gpLinks.Split(']', '[').Where(x => x.StartsWith("LDAP")))
                {
                    var split = l.Split(';');
                    var dn = split[0];
                    var status = split[1];
                    if (status.Equals("3") || status.Equals("1"))
                        continue;

                    var enforced = status.Equals("2");
                    var index = dn.IndexOf("CN=", StringComparison.OrdinalIgnoreCase) + 4;
                    var name = dn.Substring(index, index + 25).ToUpper();
                    if (!_gpoCache.ContainsKey(name)) continue;

                    var dName = _gpoCache[name];
                    links.Add(new GpLink
                    {
                        IsEnforced = enforced,
                        Name = $"{dName}@{domain}"
                    });
                }

                obj.Links = links.ToArray();
            }

            var computers = new List<string>();
            var users = new List<string>();
            var ous = new List<string>();
            foreach (var subEntry in _utils.DoSearch(
                "(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))",
                SearchScope.OneLevel,
                new[]
                {
                    "samaccountname", "name", "objectguid", "objectclass", "objectsid", "samaccounttype", "dnshostname"
                }, domain, entry.DistinguishedName))
            {
                var subResolved = subEntry.ResolveAdEntry();

                if (subResolved == null)
                    continue;

                if (subResolved.ObjectType.Equals("ou"))
                {
                    ous.Add(new Guid(subEntry.GetPropBytes("objectguid")).ToString().ToUpper());
                }
                else if (subResolved.ObjectType.Equals("computer"))
                {
                    computers.Add(subResolved.BloodHoundDisplay);
                }
                else
                {
                    users.Add(subResolved.BloodHoundDisplay);
                }
            }

            foreach (var container in _utils.DoSearch("(objectclass=container)", SearchScope.OneLevel,
                new[] { "name", "distinguishedname" }, domain))
            {
                foreach (var subEntry in _utils.DoSearch("(|(samAccountType=805306368)(samAccountType=805306369))",
                    SearchScope.Subtree, new[] { "samaccounttype", "samaccountname", "distinguishedname", "dnshostname", "objectsid" },
                    domain, container.DistinguishedName))
                {
                    var subResolved = subEntry.ResolveAdEntry();
                    if (subResolved == null)
                    {
                        continue;
                    }
                    if (subResolved.ObjectType.Equals("computer"))
                    {
                        computers.Add(subResolved.BloodHoundDisplay);
                    }
                    else
                    {
                        users.Add(subResolved.BloodHoundDisplay);
                    }
                }
            }

            obj.Users = users.ToArray();

            obj.Computers = computers.ToArray();

            obj.ChildOus = ous.ToArray();
        }
    }
}
