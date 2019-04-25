using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Reflection;
using Sharphound2.JsonObjects;
using GroupMember = Sharphound2.JsonObjects.GroupMember;

namespace Sharphound2.Enumeration
{
    internal static class GroupHelpers
    {
        private static Utils _utils;
        private static Cache _cache;
        private static readonly string[] Props = { "samaccountname", "distinguishedname", "samaccounttype", "dnshostname" };
        public static void Init()
        {
            _utils = Utils.Instance;
            _cache = Cache.Instance;
        }

        public static void GetGroupInfo(SearchResultEntry entry, ResolvedEntry resolved, string domainSid, ref Group u)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.Group))
                return;

            var fMembers = new List<GroupMember>();
            var principalDisplayName = resolved.BloodHoundDisplay;
            var principalDomainName = Utils.ConvertDnToDomain(entry.DistinguishedName);

            if (resolved.ObjectType == "group")
                _cache.AddMapValue(entry.DistinguishedName, "group", principalDisplayName);

            var members = entry.GetPropArray("member");

            if (members.Length == 0)
            {
                var tempMembers = new List<string>();
                var bottom = 0;

                while (true)
                {
                    var top = bottom + 1499;
                    var range = $"member;range={bottom}-{top}";
                    bottom += 1500;
                    //Try ranged retrieval
                    var result = _utils.DoSearch("(objectclass=*)", SearchScope.Base, new[] {range},
                        principalDomainName,
                        entry.DistinguishedName).DefaultIfEmpty(null).FirstOrDefault();

                    //We didn't get an object back. Break out of the loop
                    if (result?.Attributes.AttributeNames == null)
                    {
                        break;
                    }
                    var en = result.Attributes.AttributeNames.GetEnumerator();

                    //If the enumerator fails, that means theres really no members at all
                    if (!en.MoveNext())
                    {
                        break;
                    }

                    if (en.Current == null)
                    {
                        continue;
                    }
                    var attrib = en.Current.ToString();
                    if (attrib.EndsWith("-*"))
                    {
                        //We're done here, no more members to grab
                        break;
                    }
                    tempMembers.AddRange(result.GetPropArray(attrib));
                    
                }

                members = tempMembers.ToArray();
            }

            foreach (var dn in members)
            {
                //Check our cache first
                if (!_cache.GetMapValueUnknownType(dn, out var principal))
                {
                    if (dn.Contains("ForeignSecurityPrincipals"))
                    {
                        var sid = dn.Split(',')[0].Substring(3);
                        if (dn.Contains("CN=S-1-5-21"))
                        {
                            var domain = _utils.SidToDomainName(sid);
                            if (domain == null)
                            {
                                Utils.Verbose($"Unable to resolve domain for FSP {dn}");
                                continue;
                            }

                            principal = _utils.UnknownSidTypeToDisplay(sid, domain, Props);
                        }
                        else
                        {
                            if (!MappedPrincipal.GetCommon(sid, out principal))
                            {
                                continue;
                            }

                            principal.PrincipalName = $"{principal.PrincipalName}@{principalDomainName}";
                        }
                    }
                    else
                    {
                        var objEntry = _utils
                            .DoSearch("(objectclass=*)", SearchScope.Base, Props, Utils.ConvertDnToDomain(dn), dn)
                            .DefaultIfEmpty(null).FirstOrDefault();

                        if (objEntry == null)
                        {
                            principal = null;
                        }
                        else
                        {
                            var resolvedObj = objEntry.ResolveAdEntry();
                            if (resolvedObj == null || resolvedObj.ObjectType == "domain")
                                principal = null;
                            else
                            {
                                _cache.AddMapValue(dn, resolvedObj.ObjectType, resolvedObj.BloodHoundDisplay);
                                principal = new MappedPrincipal
                                (
                                    resolvedObj.BloodHoundDisplay,
                                    resolvedObj.ObjectType
                                );
                            }
                        }
                    }
                }

                if (principal != null)
                {
                    fMembers.Add(new GroupMember
                    {
                        MemberName = principal.PrincipalName,
                        MemberType = principal.ObjectType
                    });
                }
            }

            u.Members = fMembers.Distinct().ToArray();
        }

        internal static void GetGroupInfo(SearchResultEntry entry, ResolvedEntry resolved, string domainSid, ref User u)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.Group))
                return;

            var pgi = entry.GetProp("primarygroupid");
            if (pgi == null) return;

            var pgsid = $"{domainSid}-{pgi}";
            var primaryGroupName = _utils.SidToDisplay(pgsid, Utils.ConvertDnToDomain(entry.DistinguishedName), Props, "group");
            u.PrimaryGroup = primaryGroupName;
        }

        internal static void GetGroupInfo(SearchResultEntry entry, ResolvedEntry resolved, string domainSid, ref Computer u)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.Group))
                return;

            var pgi = entry.GetProp("primarygroupid");
            if (pgi == null) return;

            var pgsid = $"{domainSid}-{pgi}";
            var primaryGroupName = _utils.SidToDisplay(pgsid, Utils.ConvertDnToDomain(entry.DistinguishedName), Props, "group");
            u.PrimaryGroup = primaryGroupName;
        }

        #region Pinvoke
        public enum AdsTypes
        {
            AdsNameTypeDn = 1,
            AdsNameTypeCanonical = 2,
            AdsNameTypeNt4 = 3,
            AdsNameTypeDisplay = 4,
            AdsNameTypeDomainSimple = 5,
            AdsNameTypeEnterpriseSimple = 6,
            AdsNameTypeGuid = 7,
            AdsNameTypeUnknown = 8,
            AdsNameTypeUserPrincipalName = 9,
            AdsNameTypeCanonicalEx = 10,
            AdsNameTypeServicePrincipalName = 11,
            AdsNameTypeSidOrSidHistoryName = 12
        }

        public static string ConvertAdName(string objectName, AdsTypes inputType, AdsTypes outputType)
        {
            string domain;

            if (inputType.Equals(AdsTypes.AdsNameTypeNt4))
            {
                objectName = objectName.Replace("/", "\\");
            }

            switch (inputType)
            {
                case AdsTypes.AdsNameTypeNt4:
                    domain = objectName.Split('\\')[0];
                    break;
                case AdsTypes.AdsNameTypeDomainSimple:
                    domain = objectName.Split('@')[1];
                    break;
                case AdsTypes.AdsNameTypeCanonical:
                    domain = objectName.Split('/')[0];
                    break;
                case AdsTypes.AdsNameTypeDn:
                    domain = objectName.Substring(objectName.IndexOf("DC=", StringComparison.Ordinal)).Replace("DC=", "").Replace(",", ".");
                    break;
                default:
                    domain = "";
                    break;
            }

            try
            {
                var translateName = Type.GetTypeFromProgID("NameTranslate");
                var translateInstance = Activator.CreateInstance(translateName);

                var args = new object[2];
                args[0] = 1;
                args[1] = domain;
                translateName.InvokeMember("Init", BindingFlags.InvokeMethod, null, translateInstance, args);

                args = new object[2];
                args[0] = (int)inputType;
                args[1] = objectName;
                translateName.InvokeMember("Set", BindingFlags.InvokeMethod, null, translateInstance, args);

                args = new object[1];
                args[0] = (int)outputType;

                var result = (string)translateName.InvokeMember("Get", BindingFlags.InvokeMethod, null, translateInstance, args);

                return result;
            }
            catch
            {
                return null;
            }
        }
        #endregion
    }
}
