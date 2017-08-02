using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using System.Security.Principal;
using Sharphound2.OutputObjects;

namespace Sharphound2.Enumeration
{
    internal static class AclHelpers
    {
        private static Utils _utils;
        private static ConcurrentDictionary<string, byte> _nullSids;
        private static string[] _props;
        private static ConcurrentDictionary<string, DcSync> _syncers;
        

        public static void Init()
        {
            _utils = Utils.Instance;
            _nullSids = new ConcurrentDictionary<string, byte>();
            _props = new[] {"distinguishedname", "samaccounttype", "samaccountname", "dnshostname"};
            _syncers = new ConcurrentDictionary<string, DcSync>();
        }

        public static void ClearSyncers()
        {
            _syncers = new ConcurrentDictionary<string, DcSync>();
        }

        public static List<ACL> GetSyncers()
        {
            var toReturn = new List<ACL>();

            foreach (var key in _syncers.Keys)
            {
                if (!_syncers.TryGetValue(key, out DcSync temp)) continue;
                if (temp.CanDCSync())
                {
                    toReturn.Add(temp.GetOutputObj());
                }
            }
            return toReturn;
        }

        public static List<ACL> ProcessAdObject(SearchResultEntry entry, string domainName)
        {
            var toReturn = new List<ACL>();
            var ntSecurityDescriptor = entry.GetPropBytes("ntsecuritydescriptor");
            if (ntSecurityDescriptor == null)
            {
                return toReturn;
            }

            var descriptor = new RawSecurityDescriptor(ntSecurityDescriptor, 0);
            var rawAcl = descriptor.DiscretionaryAcl;
            var ownerSid = descriptor.Owner.ToString();
            var entryDisplayName = entry.ResolveBloodhoundDisplay();
            var entryType = entry.GetObjectType();
            
            //Determine the owner of the object
            if (!_nullSids.TryGetValue(ownerSid, out byte _))
            {
                if (!MappedPrincipal.GetCommon(ownerSid, out MappedPrincipal owner))
                {
                    var ownerDomain = _utils.SidToDomainName(ownerSid) ?? domainName;
                    owner = _utils.UnknownSidTypeToDisplay(ownerSid, ownerDomain, _props);
                }

                if (owner != null)
                {
                    toReturn.Add(new ACL
                    {
                        PrincipalName = $"{owner.PrincipalName}@{domainName}",
                        PrincipalType = owner.ObjectType,
                        Inherited = false,
                        RightName = "Owner",
                        AceType = "",
                        ObjectName = entryDisplayName,
                        ObjectType = entryType,
                        Qualifier = "AccessAllowed"
                    });
                }
                else
                {
                    _nullSids.TryAdd(ownerSid, new byte());
                }
            }

            foreach (var genericAce in rawAcl)
            {
                var qAce = (QualifiedAce) genericAce;
                var objectSid = qAce.SecurityIdentifier.ToString();

                if (_nullSids.TryGetValue(objectSid, out byte _))
                    continue;

                if (!MappedPrincipal.GetCommon(objectSid, out MappedPrincipal mappedPrincipal))
                {
                    var objectDomain =
                        _utils.SidToDomainName(objectSid) ??
                        domainName;
                    mappedPrincipal = _utils.UnknownSidTypeToDisplay(objectSid, objectDomain, _props);
                    if (mappedPrincipal == null)
                    {
                        _nullSids.TryAdd(objectSid, new byte());
                        continue;
                    }
                }

                //We have a principal and we've successfully resolved the object. Lets process stuff!
                var adRight = (ActiveDirectoryRights) Enum.ToObject(typeof(ActiveDirectoryRights), qAce.AccessMask);
                var adRightString = adRight.ToString();
                var ace = qAce as ObjectAce;
                var guid = ace != null ? ace.ObjectAceType.ToString() : "";
                var toContinue = false;

                //Figure out if we need more processing
                toContinue |= (adRightString.Contains("WriteDacl") || adRightString.Contains("WriteOwner"));
                if (adRightString.Contains("GenericWrite") || adRightString.Contains("GenericAll"))
                    toContinue |= ("00000000-0000-0000-0000-000000000000".Equals(guid) || guid.Equals("") || toContinue);

                if (adRightString.Contains("ExtendedRight"))
                {
                    toContinue |= (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("") || guid.Equals("00299570-246d-11d0-a768-00aa006e0529") || toContinue);

                    //DCSync
                    toContinue |= (guid.Equals("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") || guid.Equals("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") || toContinue);
                }

                if (adRightString.Contains("WriteProperty"))
                    toContinue |= (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2") || guid.Equals("bf9679a8-0de6-11d0-a285-00aa003049e2") || toContinue);

                if (!toContinue)
                {
                    continue;
                }

                string aceType = null;
                if (adRightString.Contains("ExtendedRight"))
                {
                    switch (guid)
                    {
                        case "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
                            aceType = "DS-Replication-Get-Changes";
                            break;
                        case "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
                            aceType = "DS-Replication-Get-Changes-All";
                            break;
                        default:
                            aceType = "All";
                            break;
                    }
                }

                if (aceType != null && (aceType.Equals("DS-Replication-Get-Changes-All") ||
                                        aceType.Equals("DS-Replication-Get-Changes")))
                {
                    if (!_syncers.TryGetValue(mappedPrincipal.PrincipalName, out DcSync sync))
                    {
                        sync = new DcSync
                        {
                            Domain =  entryDisplayName,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType
                        };
                    }

                    if (aceType.Contains("-All"))
                    {
                        sync.GetChangesAll = true;
                    }
                    else
                    {
                        sync.GetChanges = true;
                    }

                    _syncers.AddOrUpdate(mappedPrincipal.PrincipalName, sync, (key, oldVar) => sync);
                    continue;
                }

                if (adRightString.Contains("GenericAll"))
                {
                    toReturn.Add(new ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        ObjectType = entryType,
                        ObjectName = entryDisplayName,
                        RightName = "GenericAll",
                        Qualifier = qAce.AceQualifier.ToString()
                    });
                }

                if (adRightString.Contains("GenericWrite"))
                {
                    toReturn.Add(new ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        ObjectType = entryType,
                        ObjectName = entryDisplayName,
                        RightName = "GenericWrite",
                        Qualifier = qAce.AceQualifier.ToString()
                    });
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    toReturn.Add(new ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        ObjectType = entryType,
                        ObjectName = entryDisplayName,
                        RightName = "WriteOwner",
                        Qualifier = qAce.AceQualifier.ToString()
                    });
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    toReturn.Add(new ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        ObjectType = entryType,
                        ObjectName = entryDisplayName,
                        RightName = "WriteDacl",
                        Qualifier = qAce.AceQualifier.ToString()
                    });
                }

                if (adRightString.Contains("WriteProperty"))
                {
                    if (guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2"))
                    {
                        toReturn.Add(new ACL
                        {
                            AceType = "Member",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            ObjectType = entryType,
                            ObjectName = entryDisplayName,
                            RightName = "WriteProperty",
                            Qualifier = qAce.AceQualifier.ToString()
                        });
                    }
                    else
                    {
                        toReturn.Add(new ACL
                        {
                            AceType = "Script-Path",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            ObjectType = entryType,
                            ObjectName = entryDisplayName,
                            RightName = "WriteProperty",
                            Qualifier = qAce.AceQualifier.ToString()
                        });
                    }
                }

                if (adRightString.Contains("ExtendedRight"))
                {
                    if (guid.Equals("00299570-246d-11d0-a768-00aa006e0529"))
                    {
                        toReturn.Add(new ACL
                        {
                            AceType = "User-Force-Change-Password",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            ObjectType = entryType,
                            ObjectName = entryDisplayName,
                            RightName = "ExtendedRight",
                            Qualifier = qAce.AceQualifier.ToString()
                        });
                    }
                    else
                    {
                        toReturn.Add(new ACL
                        {
                            AceType = "All",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            ObjectType = entryType,
                            ObjectName = entryDisplayName,
                            RightName = "ExtendedRight",
                            Qualifier = qAce.AceQualifier.ToString()
                        });
                    }
                }
            }

            return toReturn;
        }
    }
}
