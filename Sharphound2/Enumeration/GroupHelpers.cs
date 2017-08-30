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
        private static readonly string[] Props = { "samaccountname", "distinguishedname", "samaccounttype" };

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
            var principalDomainName = Utils.ConvertDnToDomain(entry.DistinguishedName);
            var principalDisplayName = resolvedEntry.BloodHoundDisplay;
            var objectType = resolvedEntry.ObjectType;

            //If this object is a group, add it to our DN cache
            if (objectType.Equals("group"))
            {
                _cache.AddMapValue(entry.DistinguishedName, "group", principalDisplayName);
            }

            foreach (var dn in entry.GetPropArray("memberof"))
            {
                //Check our cache first
                if (!_cache.GetMapValue(dn, "group", out var groupName))
                {
                    //Search for the object directly
                    var groupEntry = _utils
                        .DoSearch("(objectclass=group)", SearchScope.Base, Props, Utils.ConvertDnToDomain(dn), dn)
                        .DefaultIfEmpty(null).FirstOrDefault();

                    if (groupEntry == null)
                    {
                        //Our search didn't return anything so fallback
                        //Try convertadname first
                        groupName = ConvertAdName(dn, AdsTypes.AdsNameTypeDn, AdsTypes.AdsNameTypeNt4);

                        //If convertadname is null, just screw with the distinguishedname to get the group
                        groupName = groupName != null
                            ? groupName.Split('\\').Last()
                            : dn.Substring(0, dn.IndexOf(",", StringComparison.Ordinal)).Split('=').Last();
                    }
                    else
                    {
                        //We got an object back!
                        groupName = groupEntry.ResolveAdEntry().BloodHoundDisplay;
                    }

                    //If we got a group back, add it to the cache for later use
                    if (groupName != null)
                    {
                        _cache.AddMapValue(dn, "group", groupName);
                    }
                }

                //We got our group! Return it
                if (groupName != null)
                    yield return new GroupMember
                    {
                        AccountName = principalDisplayName,
                        GroupName = groupName,
                        ObjectType = objectType
                    };
            }

            var primaryGroupId = entry.GetProp("primarygroupid");
            if (primaryGroupId == null) yield break;
            
            //As far as I know you cant belong to a primary group of another domain
            var pgsid = $"{domainSid}-{primaryGroupId}";
            var primaryGroupName = _utils.SidToDisplay(pgsid, principalDomainName, Props, "group");
            
            if (primaryGroupName != null)
                yield return new GroupMember
                {
                    AccountName = principalDisplayName,
                    GroupName = primaryGroupName,
                    ObjectType = objectType
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
