using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using Sharphound2.JsonObjects;
using Sharphound2.OutputObjects;
using GpLink = Sharphound2.OutputObjects.GpLink;

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
                SearchScope.Subtree, new[] {"displayname", "name"}, domain))
            {
                var dName = entry.GetProp("displayname");
                var name = entry.GetProp("name");
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
            obj.BlocksInheritance = opts != null && opts.Equals("1");

            //Resolve GPLinks on the ou
            var links = new List<JsonObjects.GpLink>();

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
                    var name = dn.Substring(index, index + 25);

                    if (!_gpoCache.ContainsKey(name)) continue;

                    var dName = _gpoCache[name];
                    links.Add(new JsonObjects.GpLink
                    {
                        IsEnforced = enforced,
                        Name = $"{dName}@{resolved.BloodHoundDisplay}"
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

            if (users.Count > 0)
                obj.Users = users.ToArray();

            if (computers.Count > 0)
                obj.Computers = computers.ToArray();

            if (ous.Count > 0)
                obj.ChildOus = ous.ToArray();
        }

        internal static void ResolveContainer(SearchResultEntry entry, ResolvedEntry resolved, ref Domain obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.Container))
                return;

            var domain = Utils.ConvertDnToDomain(entry.DistinguishedName);

            //Resolve GPLinks on the domain
            var links = new List<JsonObjects.GpLink>();

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
                    var name = dn.Substring(index, index + 25);

                    if (!_gpoCache.ContainsKey(name)) continue;

                    var dName = _gpoCache[name];
                    links.Add(new JsonObjects.GpLink
                    {
                        IsEnforced = enforced,
                        Name = $"{dName}@{resolved.BloodHoundDisplay}"
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
                new[] {"name", "distinguishedname"}, domain))
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

            if (users.Count > 0)
                obj.Users = users.ToArray();

            if (computers.Count > 0)
                obj.Computers = computers.ToArray();

            if (ous.Count > 0)
                obj.ChildOus = ous.ToArray();
        }


        internal static IEnumerable<OutputBase> GetContainersForDomain(string domain)
        {
            var d = _utils.GetDomain(domain);
            if (d == null)
            {
                yield break;
            }
            domain = d.Name;
            var queue = new Queue<string>();
            var cache = new ConcurrentDictionary<string, string>();

            //Cache GPO GUIDS -> Display Name
            foreach (var entry in _utils.DoSearch("(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))",
                SearchScope.Subtree, new[] {"displayname", "name"}, domain))
            {
                var dName = entry.GetProp("displayname");
                var name = entry.GetProp("name");
                name = name.Substring(1, name.Length - 2);
                cache.TryAdd(name, dName);
            }

            //Get the base domain object
            var domainBase = _utils.DoSearch("(objectclass=*)", SearchScope.Base, new[] {"gplink", "objectguid"}, domain)
                .Take(1).First();

            var domainGuid = new Guid(domainBase.GetPropBytes("objectguid")).ToString();
            var domainGpLink = domainBase.GetProp("gplink");

            //Get GpLinks for the domain
            if (domainGpLink != null)
            {
                foreach (var t in domainGpLink.Split(']', '[').Where(x => x.StartsWith("LDAP")))
                {
                    var split = t.Split(';');
                    var dn = split[0];
                    var status = split[1];
                    if (status.Equals("3") || status.Equals("1"))
                        continue;
                    var enforced = status.Equals("2");
                    var index = dn.IndexOf("CN=", StringComparison.OrdinalIgnoreCase) + 4;
                    var name = dn.Substring(index, index + 25);

                    if (!cache.ContainsKey(name)) continue;

                    var dName = cache[name];
                    yield return new GpLink
                    {
                        GpoDisplayName = $"{dName}@{domain}",
                        IsEnforced = enforced,
                        ObjectGuid = domainGuid.ToUpper(),
                        ObjectType = "domain",
                        ObjectName = domain,
                        GpoGuid = name.ToUpper()
                    };
                }
            }

            //Find non-ou containers and enumerate the users/computers in them
            foreach (var container in _utils.DoSearch("(objectclass=container)", SearchScope.OneLevel, new[] {"name", "distinguishedname"},
                domain))
            {
                var path = container.DistinguishedName;

                foreach (var obj in _utils.DoSearch("(|(samAccountType=805306368)(samAccountType=805306369))",
                    SearchScope.Subtree, new[] {"samaccounttype", "samaccountname", "distinguishedname", "dnshostname", "objectsid"},
                    domain, path))
                {
                    var resolved = obj.ResolveAdEntry();
                    if (resolved == null)
                    {
                        continue;
                    }
                    yield return new Container
                    {
                        ContainerType = "domain",
                        ContainerBlocksInheritance = false,
                        ContainerGuid = domainGuid.ToUpper(),
                        ObjectType = resolved.ObjectType,
                        ContainerName = domain,
                        ObjectName = resolved.BloodHoundDisplay,
                        ObjectId = obj.GetSid().ToUpper()
                    };
                }
            }

            foreach (var ou in _utils.DoSearch("(objectcategory=organizationalUnit)", SearchScope.OneLevel,
                new[] {"name", "objectguid"}, domain))
            {
                var name = $"{ou.GetProp("name")}@{domain}".ToUpper();
                var guid = new Guid(ou.GetPropBytes("objectguid")).ToString();

                yield return new Container
                {
                    ContainerType = "domain",
                    ContainerName = domain,
                    ContainerGuid = domainGuid.ToUpper(),
                    ContainerBlocksInheritance = false,
                    ObjectType = "ou",
                    ObjectName = name,
                    ObjectId = guid.ToUpper()
                };

                queue.Enqueue(ou.DistinguishedName);
            }

            while (queue.Count > 0)
            {
                var distinguishedName = queue.Dequeue();
                var entry = _utils.DoSearch("(objectcategory=*)", SearchScope.Base,
                    new[] {"name", "objectguid", "gplink", "gpoptions"}, domain, distinguishedName).First();

                var guid = new Guid(entry.GetPropBytes("objectguid")).ToString();
                var ouname = entry.GetProp("name");
                var opts = entry.GetProp("gpoptions");

                var blocksInheritance = opts != null && opts.Equals("1");

                var gplink = entry.GetProp("gplink");
                if (gplink != null)
                {
                    foreach (var t in gplink.Split(']', '[').Where(x => x.StartsWith("LDAP")))
                    {
                        var split = t.Split(';');
                        var dn = split[0];
                        var status = split[1];
                        if (status.Equals("3") || status.Equals("1"))
                            continue;
                        var enforced = status.Equals("2");
                        var index = dn.IndexOf("CN=", StringComparison.OrdinalIgnoreCase) + 4;
                        var name = dn.Substring(index, index + 25);
                        if (cache.ContainsKey(name))
						{
                            var dName = cache[name];
                            yield return new GpLink
                            {
                                GpoDisplayName = $"{dName}@{domain}".ToUpper(),
                                IsEnforced = enforced,
                                ObjectGuid = guid.ToUpper(),
                                ObjectType = "ou",
                                ObjectName = $"{ouname}@{domain}".ToUpper(),
                                GpoGuid = name.ToUpper()
                            };
                        }
                    }
                }

                foreach (var sub in _utils.DoSearch(
                    "(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))",
                    SearchScope.OneLevel, new[] {"samaccountname","name", "objectguid", "gplink", "gpoptions", "objectclass", "objectsid", "samaccounttype", "dnshostname"}, domain, distinguishedName))
                {
                    var resolved = sub.ResolveAdEntry();

                    if (resolved == null)
                        continue;

                    if (resolved.ObjectType.Equals("ou"))
                    {
                        yield return new Container
                        {
                            ContainerType = "ou",
                            ContainerName = $"{ouname}@{domain}".ToUpper(),
                            ContainerGuid = guid.ToUpper(),
                            ContainerBlocksInheritance = blocksInheritance,
                            ObjectType = "ou",
                            ObjectName = resolved.BloodHoundDisplay,
                            ObjectId = new Guid(sub.GetPropBytes("objectguid")).ToString().ToUpper()
                        };
                        queue.Enqueue(sub.DistinguishedName);
                    }else
                    {
                        yield return new Container
                        {
                            ContainerType = "ou",
                            ContainerName = $"{ouname}@{domain}".ToUpper(),
                            ContainerGuid = guid.ToUpper(),
                            ContainerBlocksInheritance = blocksInheritance,
                            ObjectType = resolved.ObjectType,
                            ObjectName = resolved.BloodHoundDisplay,
                            ObjectId = sub.GetSid().ToUpper()
                        };
                    }
                }
            }
        }
    }
}
