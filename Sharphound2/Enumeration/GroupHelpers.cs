using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Reflection;
using Sharphound2.OutputObjects;

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

        /// <summary>
        /// Processes an LDAP entry to resolve PrimaryGroup/MemberOf properties
        /// </summary>
        /// <param name="entry">LDAP entry</param>
        /// <param name="resolvedEntry">The resolved object with the name/type of the entry</param>
        /// <param name="domainSid">SID for the domain being enumerated. Used to resolve PrimaryGroupID</param>
        /// <returns></returns>
        public static IEnumerable<GroupMember> ProcessAdObject(SearchResultEntry entry, ResolvedEntry resolvedEntry, string domainSid)
        {
            var principalDisplayName = resolvedEntry.BloodHoundDisplay;
            var principalDomainName = Utils.ConvertDnToDomain(entry.DistinguishedName);

            //If this object is a group, add it to our DN cache
            if (resolvedEntry.ObjectType.Equals("group"))
                _cache.AddMapValue(entry.DistinguishedName, "group", principalDisplayName);
            
            foreach (var dn in entry.GetPropArray("member"))
            {
                //Check our cache first
                if (!_cache.GetMapValueUnknownType(dn, out var principal))
                {
                    if (dn.Contains("ForeignSecurityPrincipals") && !dn.StartsWith("CN=S-1-5-21"))
                    {
                        if (dn.Contains("S-1-5-21"))
                        {
                            var sid = entry.GetProp("cn");
                            principal = _utils.UnknownSidTypeToDisplay(sid, _utils.SidToDomainName(sid), Props);
                        }
                        else
                        {
                            principal = null;
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

                            _cache.AddMapValue(dn, resolvedObj.ObjectType, resolvedObj.BloodHoundDisplay);
                            principal = new MappedPrincipal
                            (
                                resolvedObj.BloodHoundDisplay,
                                resolvedObj.ObjectType
                            );
                        }
                    }
                }

                

                if (principal != null)
                {
                    yield return new GroupMember
                    {
                        AccountName = principal.PrincipalName,
                        GroupName = principalDisplayName,
                        ObjectType = principal.ObjectType
                    };
                }
            }

            var pgi = entry.GetProp("primarygroupid");
            if (pgi == null) yield break;

            var pgsid = $"{domainSid}-{pgi}";
            var primaryGroupName = _utils.SidToDisplay(pgsid, principalDomainName, Props, "group");

            if (primaryGroupName != null)
                yield return new GroupMember
                {
                    AccountName = resolvedEntry.BloodHoundDisplay,
                    GroupName = primaryGroupName,
                    ObjectType = resolvedEntry.ObjectType
                };
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
