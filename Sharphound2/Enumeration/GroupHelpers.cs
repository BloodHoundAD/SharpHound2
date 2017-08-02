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


        public static void Init()
        {
            _utils = Utils.Instance;
            _cache = Cache.Instance;
        }

        public static List<GroupMember> ProcessAdObject(SearchResultEntry entry, string domainSid)
        {
            var toReturn = new List<GroupMember>();
            string[] props = { "samaccountname", "distinguishedname", "samaccounttype" };
            
            if (!_cache.GetMapValue(entry.DistinguishedName, entry.GetObjectType(), out string principalDisplayName))
            {
                principalDisplayName = entry.ResolveBloodhoundDisplay();
            }

            if (principalDisplayName == null)
            {
                Console.WriteLine($"null principal {entry.DistinguishedName}");
                return toReturn;
            }

            var principalDomainName = Utils.ConvertDnToDomain(entry.DistinguishedName);

            var objectType = entry.GetObjectType();

            if (objectType.Equals("group"))
            {
                _cache.AddMapValue(entry.DistinguishedName, "group", principalDisplayName);
            }

            foreach (var dn in entry.GetPropArray("memberof"))
            {
                if (!_cache.GetMapValue(dn, "group", out string groupName))
                {
                    using (var conn = _utils.GetLdapConnection(principalDomainName))
                    {
                        var response = (SearchResponse)conn.SendRequest(_utils.GetSearchRequest("(objectClass=group)", SearchScope.Base, props, Utils.ConvertDnToDomain(dn), dn));

                        if (response != null && response.Entries.Count >= 1)
                        {
                            var e = response.Entries[0];
                            groupName = e.ResolveBloodhoundDisplay();
                        }
                        else
                        {
                            groupName = ConvertADName(dn, ADSTypes.ADS_NAME_TYPE_DN, ADSTypes.ADS_NAME_TYPE_NT4);
                            groupName = groupName != null ? groupName.Split('\\').Last() : dn.Substring(0, dn.IndexOf(",", StringComparison.Ordinal)).Split('=').Last();
                        }
                    }

                    if (groupName != null)
                    {
                        _cache.AddMapValue(dn, "group", groupName);
                    }

                }

                if (groupName != null)
                    toReturn.Add(new GroupMember
                    {
                        AccountName = principalDisplayName,
                        GroupName = groupName,
                        ObjectType = objectType
                    });
            }

            var primaryGroupId = entry.GetProp("primarygroupid");
            if (primaryGroupId != null)
            {
                var pgsid = $"{domainSid}-{primaryGroupId}";
                var groupName = _utils.SidToDisplay(pgsid, principalDomainName, props, "group");
                
                if (groupName != null)
                    toReturn.Add(new GroupMember
                    {
                        AccountName = principalDisplayName,
                        GroupName = groupName,
                        ObjectType = objectType
                    });
            }

            return toReturn;
        }

        #region Pinvoke
        public enum ADSTypes
        {
            ADS_NAME_TYPE_DN = 1,
            ADS_NAME_TYPE_CANONICAL = 2,
            ADS_NAME_TYPE_NT4 = 3,
            ADS_NAME_TYPE_DISPLAY = 4,
            ADS_NAME_TYPE_DOMAIN_SIMPLE = 5,
            ADS_NAME_TYPE_ENTERPRISE_SIMPLE = 6,
            ADS_NAME_TYPE_GUID = 7,
            ADS_NAME_TYPE_UNKNOWN = 8,
            ADS_NAME_TYPE_USER_PRINCIPAL_NAME = 9,
            ADS_NAME_TYPE_CANONICAL_EX = 10,
            ADS_NAME_TYPE_SERVICE_PRINCIPAL_NAME = 11,
            ADS_NAME_TYPE_SID_OR_SID_HISTORY_NAME = 12
        }

        public static string ConvertADName(string objectName, ADSTypes inputType, ADSTypes outputType)
        {
            string domain;

            if (inputType.Equals(ADSTypes.ADS_NAME_TYPE_NT4))
            {
                objectName = objectName.Replace("/", "\\");
            }

            switch (inputType)
            {
                case ADSTypes.ADS_NAME_TYPE_NT4:
                    domain = objectName.Split('\\')[0];
                    break;
                case ADSTypes.ADS_NAME_TYPE_DOMAIN_SIMPLE:
                    domain = objectName.Split('@')[1];
                    break;
                case ADSTypes.ADS_NAME_TYPE_CANONICAL:
                    domain = objectName.Split('/')[0];
                    break;
                case ADSTypes.ADS_NAME_TYPE_DN:
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
