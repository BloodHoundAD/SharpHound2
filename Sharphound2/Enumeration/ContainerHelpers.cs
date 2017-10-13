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
            domain = _utils.GetDomain(domain).Name;
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
                    var enforced = split[1].Equals("2");
                    var index = dn.IndexOf("CN=", StringComparison.Ordinal) + 4;
                    var name = dn.Substring(index, index + 25);
                    var dName = cache[name];
                    yield return new GpLink
                    {
                        GpoDisplayName = dName,
                        IsEnforced = enforced,
                        ObjectGuid = domainGuid,
                        ObjectType = "domain",
                        ObjectName = domain,
                        GpoGuid = name
                    };
                }
            }

            foreach (var container in _utils.DoSearch("(objectclass=container)", SearchScope.OneLevel, new[] {"name", "distinguishedname"},
                domain))
            {
                var name = container.GetProp("name");
                var path = container.DistinguishedName;

                foreach (var obj in _utils.DoSearch("(|(samAccountType=805306368)(samAccountType=805306369))",
                    SearchScope.Subtree, new[] {"samaccounttype", "samaccountname", "distinguishedname", "dnshostname"},
                    domain, path))
                {
                    var resolved = obj.ResolveAdEntry();
                    yield return new Container
                    {
                        ContainerType = "domain",
                        ContainerBlocksInheritance = false,
                        ContainerGuid = domainGuid,
                        ObjectType = resolved.ObjectType,
                        //Is this supposed to be the domain or the containername
                        ContainerName = name,
                        ObjectName = resolved.BloodHoundDisplay
                    };
                }
            }

            foreach (var ou in _utils.DoSearch("(objectcategory=organizationalUnit)", SearchScope.OneLevel,
                new[] {"name"}, domain))
            {
                var name = ou.GetProp("name");

                yield return new Container
                {
                    ContainerType = "domain",
                    ContainerName = domain,
                    ContainerGuid = domainGuid,
                    ContainerBlocksInheritance = false,
                    ObjectType = "ou",
                    ObjectName = name
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
                        var enforced = split[1].Equals("2");
                        var index = dn.IndexOf("CN=", StringComparison.CurrentCultureIgnoreCase) + 4;
                        var name = dn.Substring(index, index + 25);
                        var dName = cache[name];
                        yield return new GpLink
                        {
                            GpoDisplayName = dName,
                            IsEnforced = enforced,
                            ObjectGuid = guid,
                            ObjectType = "ou",
                            ObjectName = ouname,
                            GpoGuid = name
                        };
                    }
                }

                foreach (var sub in _utils.DoSearch(
                    "(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))",
                    SearchScope.OneLevel, new[] {"name", "objectguid", "gplink", "gpoptions", "objectclass"}, domain, distinguishedName))
                {
                    var objClass = sub.GetProp("objectclass");
                    var subName = sub.GetProp("name");

                    if (objClass.Contains("organizationalunit"))
                    {
                        yield return new Container
                        {
                            ContainerType = "ou",
                            ContainerName = ouname,
                            ContainerGuid = guid,
                            ContainerBlocksInheritance = blocksInheritance,
                            ObjectType = "ou",
                            ObjectName = subName
                        };
                    }else if (objClass.Contains("computer"))
                    {
                        yield return new Container
                        {
                            ContainerType = "ou",
                            ContainerName = ouname,
                            ContainerGuid = guid,
                            ContainerBlocksInheritance = blocksInheritance,
                            ObjectType = "computer",
                            ObjectName = subName
                        };
                    }
                    else
                    {
                        yield return new Container
                        {
                            ContainerType = "ou",
                            ContainerName = ouname,
                            ContainerGuid = guid,
                            ContainerBlocksInheritance = blocksInheritance,
                            ObjectType = "user",
                            ObjectName = subName
                        };
                    }
                }
            }
        }
    }
}
