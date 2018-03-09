using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using Sharphound2.OutputObjects;

namespace Sharphound2.Enumeration
{
    internal class ContainerHelpers
    {
        private static Utils _utils;

        public static void Init()
        {
            _utils = Utils.Instance;
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

            foreach (var entry in _utils.DoSearch("(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))",
                SearchScope.Subtree, new[] {"displayname", "name"}, domain))
            {
                var dName = entry.GetProp("displayname");
                var name = entry.GetProp("name");
                name = name.Substring(1, name.Length - 2);
                cache.TryAdd(name, dName);
            }

            var domainBase = _utils.DoSearch("(objectclass=*)", SearchScope.Base, new[] {"gplink", "objectguid"}, domain)
                .Take(1).First();

            var domainGuid = new Guid(domainBase.GetPropBytes("objectguid")).ToString();
            var domainGpLink = domainBase.GetProp("gplink");

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
                    if (cache.ContainsKey(name))
                    {
                        var dName = cache[name];
                        yield return new GpLink
                        {
                            GpoDisplayName = $"{dName}@{domain}",
                            IsEnforced = enforced,
                            ObjectGuid = domainGuid,
                            ObjectType = "domain",
                            ObjectName = domain,
                            GpoGuid = name
                        };
                    }
                }
            }

            foreach (var container in _utils.DoSearch("(objectclass=container)", SearchScope.OneLevel, new[] {"name", "distinguishedname"},
                domain))
            {
                var path = container.DistinguishedName;

                foreach (var obj in _utils.DoSearch("(|(samAccountType=805306368)(samAccountType=805306369))",
                    SearchScope.Subtree, new[] {"samaccounttype", "samaccountname", "distinguishedname", "dnshostname", "objectsid"},
                    domain, path))
                {
                    var resolved = obj.ResolveAdEntry();
                    yield return new Container
                    {
                        ContainerType = "domain",
                        ContainerBlocksInheritance = false,
                        ContainerGuid = domainGuid,
                        ObjectType = resolved.ObjectType,
                        ContainerName = domain,
                        ObjectName = resolved.BloodHoundDisplay,
                        ObjectId = obj.GetSid()
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
                    ContainerGuid = domainGuid,
                    ContainerBlocksInheritance = false,
                    ObjectType = "ou",
                    ObjectName = name,
                    ObjectId = guid
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
                                ObjectGuid = guid,
                                ObjectType = "ou",
                                ObjectName = $"{ouname}@{domain}".ToUpper(),
                                GpoGuid = name
                            };
                        }
                    }
                }

                foreach (var sub in _utils.DoSearch(
                    "(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))",
                    SearchScope.OneLevel, new[] {"samaccountname","name", "objectguid", "gplink", "gpoptions", "objectclass", "objectsid", "samaccounttype", "dnshostname"}, domain, distinguishedName))
                {
                    var resolved = sub.ResolveAdEntry();

                    if (resolved.ObjectType.Equals("organizationalunit"))
                    {
                        yield return new Container
                        {
                            ContainerType = "ou",
                            ContainerName = $"{ouname}@{domain}".ToUpper(),
                            ContainerGuid = guid,
                            ContainerBlocksInheritance = blocksInheritance,
                            ObjectType = "ou",
                            ObjectName = resolved.BloodHoundDisplay,
                            ObjectId = new Guid(sub.GetPropBytes("objectguid")).ToString()
                        };
                    }else
                    {
                        yield return new Container
                        {
                            ContainerType = "ou",
                            ContainerName = $"{ouname}@{domain}".ToUpper(),
                            ContainerGuid = guid,
                            ContainerBlocksInheritance = blocksInheritance,
                            ObjectType = resolved.ObjectType,
                            ObjectName = resolved.BloodHoundDisplay,
                            ObjectId = sub.GetSid()
                        };
                    }
                }
            }
        }
    }
}
