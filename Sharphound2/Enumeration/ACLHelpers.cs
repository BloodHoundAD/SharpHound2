using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using Sharphound2.JsonObjects;
using Sharphound2.OutputObjects;
using ACL = Sharphound2.OutputObjects.ACL;

namespace Sharphound2.Enumeration
{
    internal static class AclHelpers
    {
        private static Utils _utils;
        private static ConcurrentDictionary<string, byte> _nullSids;
        private static readonly string[] Props = { "distinguishedname", "samaccounttype", "samaccountname", "dnshostname" };
        private static ConcurrentDictionary<string, DcSync> _syncers;
        

        public static void Init()
        {
            _utils = Utils.Instance;
            _nullSids = new ConcurrentDictionary<string, byte>();
            _syncers = new ConcurrentDictionary<string, DcSync>();
        }

        /// <summary>
        /// Clear's the DCSync data from the dictionary
        /// </summary>
        internal static void ClearSyncers()
        {
            _syncers = new ConcurrentDictionary<string, DcSync>();
        }

        /// <summary>
        /// Returns a list of ACL items that represent principals that can DCSync
        /// </summary>
        /// <returns>List of ACL objects representing DCSyncer</returns>
        internal static List<ACL> GetSyncers()
        {
            var toReturn = new List<ACL>();

            foreach (var key in _syncers.Keys)
            {
                if (!_syncers.TryGetValue(key, out var temp)) continue;
                toReturn.AddRange(temp.GetAcls());
            }
            return toReturn;
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Domain u)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ACL))
                return;

            var aces = new List<JsonObjects.ACL>();
            var ntSecurityDescriptor = entry.GetPropBytes("ntsecuritydescriptor");
            //If the ntsecuritydescriptor is null, no point in continuing
            //I'm still not entirely sure what causes this, but it can happen
            if (ntSecurityDescriptor == null)
            {
                return;
            }

            var domainName = Utils.ConvertDnToDomain(entry.DistinguishedName);

            //Convert the ntsecuritydescriptor bytes to a .net object
            var descriptor = new RawSecurityDescriptor(ntSecurityDescriptor, 0);

            //Grab the DACL
            var rawAcl = descriptor.DiscretionaryAcl;
            //Grab the Owner
            var ownerSid = descriptor.Owner.ToString();

            //Determine the owner of the object. Start by checking if we've already determined this is null
            if (!_nullSids.TryGetValue(ownerSid, out _))
            {
                //Check if its a common SID
                if (!MappedPrincipal.GetCommon(ownerSid, out var owner))
                {
                    //Resolve the sid manually if we still dont have it
                    var ownerDomain = _utils.SidToDomainName(ownerSid) ?? domainName;
                    owner = _utils.UnknownSidTypeToDisplay(ownerSid, ownerDomain, Props);
                }
                else
                {
                    owner.PrincipalName = $"{owner.PrincipalName}@{domainName}";
                }

                //Filter out the Local System principal which pretty much every entry has
                if (owner != null && !owner.PrincipalName.Contains("LOCAL SYSTEM") && !owner.PrincipalName.Contains("CREATOR OWNER"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        RightName = "Owner",
                        Inherited = false,
                        PrincipalName = owner.PrincipalName,
                        PrincipalType = owner.ObjectType,
                        Qualifier = "AccessAllowed"
                    });
                }
                else
                {
                    //We'll cache SIDs we've failed to resolve previously so we dont keep trying
                    _nullSids.TryAdd(ownerSid, new byte());
                }
            }

            foreach (var genericAce in rawAcl)
            {
                var qAce = genericAce as QualifiedAce;
                if (qAce == null)
                    continue;

                var objectSid = qAce.SecurityIdentifier.ToString();
                if (_nullSids.TryGetValue(objectSid, out _))
                    continue;

                //Check if its a common sid
                if (!MappedPrincipal.GetCommon(objectSid, out var mappedPrincipal))
                {
                    //If not common, lets resolve it normally
                    var objectDomain =
                        _utils.SidToDomainName(objectSid) ??
                        domainName;
                    mappedPrincipal = _utils.UnknownSidTypeToDisplay(objectSid, objectDomain, Props);
                    if (mappedPrincipal == null)
                    {
                        _nullSids.TryAdd(objectSid, new byte());
                        continue;
                    }
                }
                else
                {
                    mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{domainName}";
                }

                if (mappedPrincipal.PrincipalName.Contains("LOCAL SYSTEM") || mappedPrincipal.PrincipalName.Contains("CREATOR OWNER"))
                    continue;

                //Convert our right to an ActiveDirectoryRight enum object, and then to a string
                var adRight = (ActiveDirectoryRights)Enum.ToObject(typeof(ActiveDirectoryRights), qAce.AccessMask);
                var adRightString = adRight.ToString();

                //Get the ACE for our right
                var ace = qAce as ObjectAce;
                var guid = ace != null ? ace.ObjectAceType.ToString() : "";

                var inheritedObjectType = ace != null ? ace.InheritedObjectAceType.ToString() : "00000000-0000-0000-0000-000000000000";

                var isInherited = inheritedObjectType == "00000000-0000-0000-0000-000000000000" ||
                                  inheritedObjectType == "19195a5a-6da0-11d0-afd3-00c04fd930c9";

                //Special case used for example by Exchange: the ACE is inherited but also applies to the object it is set on
                // this is verified by looking if this ACE is not inherited, and is not an inherit-only ACE
                if (!isInherited && !((ace.AceFlags & AceFlags.InheritOnly) == AceFlags.InheritOnly) && (ace.AceFlags & AceFlags.Inherited) != AceFlags.Inherited)
                {
                    //If these conditions hold the ACE applies to this object anyway
                    isInherited = true;
                }

                if (!isInherited)
                    continue;

                var toContinue = false;

                //Interesting Group ACEs - GenericAll, WriteDacl, WriteOwner, GenericWrite, AddMember
                toContinue |= (adRightString.Contains("WriteDacl") || adRightString.Contains("WriteOwner"));
                if (adRightString.Contains("GenericAll"))
                    toContinue |= ("00000000-0000-0000-0000-000000000000".Equals(guid) || guid.Equals("") || toContinue);

                if (adRightString.Contains("ExtendedRight"))
                {
                    toContinue |= (guid.Equals("00000000-0000-0000-0000-000000000000") ||
                                   guid.Equals("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") ||
                                   guid.Equals("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") || guid.Equals("") ||
                                   toContinue);
                }

                if (!toContinue)
                    continue;


                if (adRightString.Contains("GenericAll"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "GenericAll"
                    });
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "WriteOwner"
                    });
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "WriteDacl"
                    });
                }

                if (adRightString.Contains("ExtendedRight"))
                {
                    if (guid.Equals("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"))
                    {
                        aces.Add(new JsonObjects.ACL
                        {
                            AceType = "GetChanges",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            Qualifier = qAce.AceQualifier.ToString(),
                            RightName = "ExtendedRight"
                        });
                    }else if (guid.Equals("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"))
                    {
                        aces.Add(new JsonObjects.ACL
                        {
                            AceType = "GetChangesAll",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            Qualifier = qAce.AceQualifier.ToString(),
                            RightName = "ExtendedRight"
                        });
                    }
                    else
                    {
                        aces.Add(new JsonObjects.ACL
                        {
                            AceType = "All",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            Qualifier = qAce.AceQualifier.ToString(),
                            RightName = "ExtendedRight"
                        });
                    }

                }
            }

            u.Aces = aces.ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Group u)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ACL))
                return;

            var aces = new List<JsonObjects.ACL>();
            var ntSecurityDescriptor = entry.GetPropBytes("ntsecuritydescriptor");
            //If the ntsecuritydescriptor is null, no point in continuing
            //I'm still not entirely sure what causes this, but it can happen
            if (ntSecurityDescriptor == null)
            {
                return;
            }

            var domainName = Utils.ConvertDnToDomain(entry.DistinguishedName);

            //Convert the ntsecuritydescriptor bytes to a .net object
            var descriptor = new RawSecurityDescriptor(ntSecurityDescriptor, 0);

            //Grab the DACL
            var rawAcl = descriptor.DiscretionaryAcl;
            //Grab the Owner
            var ownerSid = descriptor.Owner.ToString();

            //Determine the owner of the object. Start by checking if we've already determined this is null
            if (!_nullSids.TryGetValue(ownerSid, out _))
            {
                //Check if its a common SID
                if (!MappedPrincipal.GetCommon(ownerSid, out var owner))
                {
                    //Resolve the sid manually if we still dont have it
                    var ownerDomain = _utils.SidToDomainName(ownerSid) ?? domainName;
                    owner = _utils.UnknownSidTypeToDisplay(ownerSid, ownerDomain, Props);
                }
                else
                {
                    owner.PrincipalName = $"{owner.PrincipalName}@{domainName}";
                }

                //Filter out the Local System principal which pretty much every entry has
                if (owner != null && !owner.PrincipalName.Contains("LOCAL SYSTEM") && !owner.PrincipalName.Contains("CREATOR OWNER"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        RightName = "Owner",
                        Inherited = false,
                        PrincipalName = owner.PrincipalName,
                        PrincipalType = owner.ObjectType,
                        Qualifier = "AccessAllowed"
                    });
                }
                else
                {
                    //We'll cache SIDs we've failed to resolve previously so we dont keep trying
                    _nullSids.TryAdd(ownerSid, new byte());
                }
            }

            foreach (var genericAce in rawAcl)
            {
                var qAce = genericAce as QualifiedAce;
                if (qAce == null)
                    continue;

                var objectSid = qAce.SecurityIdentifier.ToString();
                if (_nullSids.TryGetValue(objectSid, out _))
                    continue;

                //Check if its a common sid
                if (!MappedPrincipal.GetCommon(objectSid, out var mappedPrincipal))
                {
                    //If not common, lets resolve it normally
                    var objectDomain =
                        _utils.SidToDomainName(objectSid) ??
                        domainName;
                    mappedPrincipal = _utils.UnknownSidTypeToDisplay(objectSid, objectDomain, Props);
                    if (mappedPrincipal == null)
                    {
                        _nullSids.TryAdd(objectSid, new byte());
                        continue;
                    }
                }
                else
                {
                    mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{domainName}";
                }

                if (mappedPrincipal.PrincipalName.Contains("LOCAL SYSTEM") || mappedPrincipal.PrincipalName.Contains("CREATOR OWNER"))
                    continue;

                //Convert our right to an ActiveDirectoryRight enum object, and then to a string
                var adRight = (ActiveDirectoryRights)Enum.ToObject(typeof(ActiveDirectoryRights), qAce.AccessMask);
                var adRightString = adRight.ToString();

                //Get the ACE for our right
                var ace = qAce as ObjectAce;
                var guid = ace != null ? ace.ObjectAceType.ToString() : "";

                var inheritedObjectType = ace != null ? ace.InheritedObjectAceType.ToString() : "00000000-0000-0000-0000-000000000000";

                var isInherited = inheritedObjectType == "00000000-0000-0000-0000-000000000000" ||
                                  inheritedObjectType == "bf967a9c-0de6-11d0-a285-00aa003049e2";

                //Special case used for example by Exchange: the ACE is inherited but also applies to the object it is set on
                // this is verified by looking if this ACE is not inherited, and is not an inherit-only ACE
                if (!isInherited && !((ace.AceFlags & AceFlags.InheritOnly) == AceFlags.InheritOnly) && (ace.AceFlags & AceFlags.Inherited) != AceFlags.Inherited)
                {
                    //If these conditions hold the ACE applies to this object anyway
                    isInherited = true;
                }

                if (!isInherited)
                    continue;

                var toContinue = false;

                //Interesting Group ACEs - GenericAll, WriteDacl, WriteOwner, GenericWrite, AddMember
                toContinue |= (adRightString.Contains("WriteDacl") || adRightString.Contains("WriteOwner"));
                if (adRightString.Contains("GenericWrite") || adRightString.Contains("GenericAll"))
                    toContinue |= ("00000000-0000-0000-0000-000000000000".Equals(guid) || guid.Equals("") || toContinue);

                if (adRightString.Contains("WriteProperty"))
                    toContinue |= (guid.Equals("00000000-0000-0000-0000-000000000000") ||
                                   (guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2")) || guid.Equals("") ||
                                   toContinue);

                if (!toContinue)
                    continue;


                if (adRightString.Contains("GenericAll"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "GenericAll"
                    });
                }

                if (adRightString.Contains("GenericWrite"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "GenericWrite"
                    });
                }

                if (adRightString.Contains("WriteProperty"))
                {
                    if (guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2"))
                    {
                        aces.Add(new JsonObjects.ACL
                        {
                            AceType = "Member",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            Qualifier = qAce.AceQualifier.ToString(),
                            RightName = "WriteProperty"
                        });
                    }
                    else
                    {
                        aces.Add(new JsonObjects.ACL
                        {
                            AceType = "",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            Qualifier = qAce.AceQualifier.ToString(),
                            RightName = "GenericWrite"
                        });
                    }
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "WriteOwner"
                    });
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "WriteDacl"
                    });
                }
            }

            u.Aces = aces.ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref User u)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ACL))
                return;

            var aces = new List<JsonObjects.ACL>();
            var ntSecurityDescriptor = entry.GetPropBytes("ntsecuritydescriptor");
            //If the ntsecuritydescriptor is null, no point in continuing
            //I'm still not entirely sure what causes this, but it can happen
            if (ntSecurityDescriptor == null)
            {
                return;
            }

            var domainName = Utils.ConvertDnToDomain(entry.DistinguishedName);

            //Convert the ntsecuritydescriptor bytes to a .net object
            var descriptor = new RawSecurityDescriptor(ntSecurityDescriptor, 0);

            //Grab the DACL
            var rawAcl = descriptor.DiscretionaryAcl;
            //Grab the Owner
            var ownerSid = descriptor.Owner.ToString();

            //Determine the owner of the object. Start by checking if we've already determined this is null
            if (!_nullSids.TryGetValue(ownerSid, out _))
            {
                //Check if its a common SID
                if (!MappedPrincipal.GetCommon(ownerSid, out var owner))
                {
                    //Resolve the sid manually if we still dont have it
                    var ownerDomain = _utils.SidToDomainName(ownerSid) ?? domainName;
                    owner = _utils.UnknownSidTypeToDisplay(ownerSid, ownerDomain, Props);
                }
                else
                {
                    owner.PrincipalName = $"{owner.PrincipalName}@{domainName}";
                }

                //Filter out the Local System principal which pretty much every entry has
                if (owner != null && !owner.PrincipalName.Contains("LOCAL SYSTEM") && !owner.PrincipalName.Contains("CREATOR OWNER"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        RightName = "Owner",
                        Inherited = false,
                        PrincipalName = owner.PrincipalName,
                        PrincipalType = owner.ObjectType,
                        Qualifier = "AccessAllowed"
                    });
                }
                else
                {
                    //We'll cache SIDs we've failed to resolve previously so we dont keep trying
                    _nullSids.TryAdd(ownerSid, new byte());
                }
            }

            foreach (var genericAce in rawAcl)
            {
                var qAce = genericAce as QualifiedAce;
                if (qAce == null)
                    continue;

                var objectSid = qAce.SecurityIdentifier.ToString();
                if (_nullSids.TryGetValue(objectSid, out _))
                    continue;

                //Check if its a common sid
                if (!MappedPrincipal.GetCommon(objectSid, out var mappedPrincipal))
                {
                    //If not common, lets resolve it normally
                    var objectDomain =
                        _utils.SidToDomainName(objectSid) ??
                        domainName;
                    mappedPrincipal = _utils.UnknownSidTypeToDisplay(objectSid, objectDomain, Props);
                    if (mappedPrincipal == null)
                    {
                        _nullSids.TryAdd(objectSid, new byte());
                        continue;
                    }
                }
                else
                {
                    mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{domainName}";
                }

                if (mappedPrincipal.PrincipalName.Contains("LOCAL SYSTEM") || mappedPrincipal.PrincipalName.Contains("CREATOR OWNER"))
                    continue;

                //Convert our right to an ActiveDirectoryRight enum object, and then to a string
                var adRight = (ActiveDirectoryRights)Enum.ToObject(typeof(ActiveDirectoryRights), qAce.AccessMask);
                var adRightString = adRight.ToString();

                //Get the ACE for our right
                var ace = qAce as ObjectAce;
                var guid = ace != null ? ace.ObjectAceType.ToString() : "";

                var inheritedObjectType = ace != null ? ace.InheritedObjectAceType.ToString() : "00000000-0000-0000-0000-000000000000";

                var isInherited = inheritedObjectType == "00000000-0000-0000-0000-000000000000" ||
                                  inheritedObjectType == "bf967aba-0de6-11d0-a285-00aa003049e2";


                //Special case used for example by Exchange: the ACE is inherited but also applies to the object it is set on
                // this is verified by looking if this ACE is not inherited, and is not an inherit-only ACE
                if (!isInherited && !((ace.AceFlags & AceFlags.InheritOnly) == AceFlags.InheritOnly) && (ace.AceFlags & AceFlags.Inherited) != AceFlags.Inherited)
                {
                    //If these conditions hold the ACE applies to this object anyway
                    isInherited = true;
                }

                if (!isInherited)
                    continue;

                var toContinue = false;

                //Interesting User ACEs - GenericAll, WriteDacl, WriteOwner, GenericWrite, ForceChangePassword
                toContinue |= (adRightString.Contains("WriteDacl") || adRightString.Contains("WriteOwner"));
                if (adRightString.Contains("GenericWrite") || adRightString.Contains("GenericAll"))
                    toContinue |= ("00000000-0000-0000-0000-000000000000".Equals(guid) || guid.Equals("") || toContinue);

                if (adRightString.Contains("ExtendedRight"))
                {
                    toContinue |= (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("") ||
                                   guid.Equals("00299570-246d-11d0-a768-00aa006e0529") || toContinue);
                }

                if (adRightString.Contains("WriteProperty"))
                    toContinue |= (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("") ||
                                   toContinue);

                if (!toContinue)
                    continue;


                if (adRightString.Contains("GenericAll"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "GenericAll"
                    });
                }

                if (adRightString.Contains("GenericWrite") || adRightString.Contains("WriteProperty"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "GenericWrite"
                    });
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "WriteOwner"
                    });
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "WriteDacl"
                    });
                }

                if (adRightString.Contains("ExtendedRight"))
                {
                    if (guid.Equals("00299570-246d-11d0-a768-00aa006e0529"))
                    {
                        aces.Add(new JsonObjects.ACL
                        {
                            AceType = "User-Force-Change-Password",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            Qualifier = qAce.AceQualifier.ToString(),
                            RightName = "ExtendedRight"
                        });
                    }
                    else if (guid.Equals("00000000-0000-0000-0000-000000000000"))
                    {
                        aces.Add(new JsonObjects.ACL
                        {
                            AceType = "All",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            Qualifier = qAce.AceQualifier.ToString(),
                            RightName = "ExtendedRight"
                        });
                    }
                }
            }

            u.Aces = aces.ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Gpo g)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ACL))
                return;

            var aces = new List<JsonObjects.ACL>();
            var ntSecurityDescriptor = entry.GetPropBytes("ntsecuritydescriptor");
            //If the ntsecuritydescriptor is null, no point in continuing
            //I'm still not entirely sure what causes this, but it can happen
            if (ntSecurityDescriptor == null)
            {
                return;
            }

            var domainName = Utils.ConvertDnToDomain(entry.DistinguishedName);

            //Convert the ntsecuritydescriptor bytes to a .net object
            var descriptor = new RawSecurityDescriptor(ntSecurityDescriptor, 0);

            //Grab the DACL
            var rawAcl = descriptor.DiscretionaryAcl;
            //Grab the Owner
            var ownerSid = descriptor.Owner.ToString();

            //Determine the owner of the object. Start by checking if we've already determined this is null
            if (!_nullSids.TryGetValue(ownerSid, out _))
            {
                //Check if its a common SID
                if (!MappedPrincipal.GetCommon(ownerSid, out var owner))
                {
                    //Resolve the sid manually if we still dont have it
                    var ownerDomain = _utils.SidToDomainName(ownerSid) ?? domainName;
                    owner = _utils.UnknownSidTypeToDisplay(ownerSid, ownerDomain, Props);
                }
                else
                {
                    owner.PrincipalName = $"{owner.PrincipalName}@{domainName}";
                }

                //Filter out the Local System principal which pretty much every entry has
                if (owner != null && !owner.PrincipalName.Contains("LOCAL SYSTEM") && !owner.PrincipalName.Contains("CREATOR OWNER"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        RightName = "Owner",
                        Inherited = false,
                        PrincipalName = owner.PrincipalName,
                        PrincipalType = owner.ObjectType,
                        Qualifier = "AccessAllowed"
                    });
                }
                else
                {
                    //We'll cache SIDs we've failed to resolve previously so we dont keep trying
                    _nullSids.TryAdd(ownerSid, new byte());
                }
            }

            foreach (var genericAce in rawAcl)
            {
                var qAce = genericAce as QualifiedAce;
                if (qAce == null)
                    continue;

                var objectSid = qAce.SecurityIdentifier.ToString();
                if (_nullSids.TryGetValue(objectSid, out _))
                    continue;

                //Check if its a common sid
                if (!MappedPrincipal.GetCommon(objectSid, out var mappedPrincipal))
                {
                    //If not common, lets resolve it normally
                    var objectDomain =
                        _utils.SidToDomainName(objectSid) ??
                        domainName;
                    mappedPrincipal = _utils.UnknownSidTypeToDisplay(objectSid, objectDomain, Props);
                    if (mappedPrincipal == null)
                    {
                        _nullSids.TryAdd(objectSid, new byte());
                        continue;
                    }
                }
                else
                {
                    mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{domainName}";
                }

                if (mappedPrincipal.PrincipalName.Contains("LOCAL SYSTEM") || mappedPrincipal.PrincipalName.Contains("CREATOR OWNER"))
                    continue;

                //Convert our right to an ActiveDirectoryRight enum object, and then to a string
                var adRight = (ActiveDirectoryRights)Enum.ToObject(typeof(ActiveDirectoryRights), qAce.AccessMask);
                var adRightString = adRight.ToString();

                //Get the ACE for our right
                var ace = qAce as ObjectAce;
                var guid = ace != null ? ace.ObjectAceType.ToString() : "";

                var inheritedObjectType = ace != null ? ace.InheritedObjectAceType.ToString() : "00000000-0000-0000-0000-000000000000";

                var isInherited = inheritedObjectType == "00000000-0000-0000-0000-000000000000" ||
                                  inheritedObjectType == "f30e3bc2-9ff0-11d1-b603-0000f80367c1";

                if (!isInherited && !((ace.AceFlags & AceFlags.InheritOnly) == AceFlags.InheritOnly) && (ace.AceFlags & AceFlags.Inherited) != AceFlags.Inherited)
                {
                    //If these conditions hold the ACE applies to this object anyway
                    isInherited = true;
                }

                if (!isInherited)
                    continue;

                var toContinue = false;

                //Interesting GPO ACEs - GenericAll, WriteDacl, WriteOwner, GenericWrite
                toContinue |= (adRightString.Contains("WriteDacl") || adRightString.Contains("WriteOwner"));
                if (adRightString.Contains("GenericAll"))
                    toContinue |= ("00000000-0000-0000-0000-000000000000".Equals(guid) || guid.Equals("") || toContinue);

                if (!toContinue)
                    continue;


                if (adRightString.Contains("GenericAll"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "GenericAll"
                    });
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "WriteOwner"
                    });
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    aces.Add(new JsonObjects.ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        Qualifier = qAce.AceQualifier.ToString(),
                        RightName = "WriteDacl"
                    });
                }
            }

            g.Aces = aces.ToArray();
        }

        /// <summary>
        /// Processes the ACL entries for an AD object
        /// </summary>
        /// <param name="entry">LDAP entry to process</param>
        /// <param name="domainName">Domain name the entry belongs too</param>
        /// <returns>A list of ACL objects for the entry</returns>
        public static IEnumerable<ACL> ProcessAdObject(SearchResultEntry entry, string domainName)
        {
            var ntSecurityDescriptor = entry.GetPropBytes("ntsecuritydescriptor");
            //If the ntsecuritydescriptor is null, no point in continuing
            //I'm still not entirely sure what causes this, but it can happen
            if (ntSecurityDescriptor == null)
            {
                yield break;
            }

            //Convert the ntsecuritydescriptor bytes to a .net object
            var descriptor = new RawSecurityDescriptor(ntSecurityDescriptor, 0);

            //Grab the DACL
            var rawAcl = descriptor.DiscretionaryAcl;
            //Grab the Owner
            var ownerSid = descriptor.Owner.ToString();

            //Resolve the entry name/type
            var resolvedEntry = entry.ResolveAdEntry();

            //If our name is null, we dont know what the principal is
            if (resolvedEntry == null)
            {
                yield break;
            }

            var entryDisplayName = resolvedEntry.BloodHoundDisplay;
            var entryType = resolvedEntry.ObjectType;
            string entryGuid;
            if (entryType.Equals("gpo"))
            {
                var n = entry.GetProp("name").ToUpper();
                entryGuid = n.Substring(1, n.Length - 2);
            }
            else
            {
                entryGuid = "";
            }

            //We have no exploitable paths for Computer, so just ignore them
            if (entryType.Equals("computer"))
                yield break;

            //Determine the owner of the object. Start by checking if we've already determined this is null
            if (!_nullSids.TryGetValue(ownerSid, out byte _))
            {
                //Check if its a common SID
                if (!MappedPrincipal.GetCommon(ownerSid, out var owner))
                {
                    //Resolve the sid manually if we still dont have it
                    var ownerDomain = _utils.SidToDomainName(ownerSid) ?? domainName;
                    owner = _utils.UnknownSidTypeToDisplay(ownerSid, ownerDomain, Props);
                }
                else
                {
                    owner.PrincipalName = $"{owner.PrincipalName}@{domainName}";
                }

                //Filter out the Local System principal which pretty much every entry has
                if (owner != null && !owner.PrincipalName.Contains("Local System"))
                {
                    yield return new ACL
                    {
                        PrincipalName = owner.PrincipalName,
                        PrincipalType = owner.ObjectType,
                        Inherited = false,
                        RightName = "Owner",
                        AceType = "",
                        ObjectName = entryDisplayName,
                        ObjectType = entryType,
                        Qualifier = "AccessAllowed",
                        ObjectGuid = entryGuid
                    };
                }
                else
                {
                    //We'll cache SIDs we've failed to resolve previously so we dont keep trying
                    _nullSids.TryAdd(ownerSid, new byte());
                }
            }

            //Loop over the actual entries in the DACL
            foreach (var genericAce in rawAcl)
            {
                var qAce = (QualifiedAce) genericAce;
                var objectSid = qAce.SecurityIdentifier.ToString();

                //If this is something we already resolved to null, just keep on moving
                if (_nullSids.TryGetValue(objectSid, out byte _))
                    continue;

                //Check if its a common sid
                if (!MappedPrincipal.GetCommon(objectSid, out var mappedPrincipal))
                {
                    //If not common, lets resolve it normally
                    var objectDomain =
                        _utils.SidToDomainName(objectSid) ??
                        domainName;
                    mappedPrincipal = _utils.UnknownSidTypeToDisplay(objectSid, objectDomain, Props);
                    if (mappedPrincipal == null)
                    {
                        _nullSids.TryAdd(objectSid, new byte());
                        continue;
                    }
                }
                else
                {
                    mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{domainName}";
                }

                //bf967a86-0de6-11d0-a285-00aa003049e2 - Computer
                //bf967aba-0de6-11d0-a285-00aa003049e2 - User
                //bf967a9c-0de6-11d0-a285-00aa003049e2 - Group
                //19195a5a-6da0-11d0-afd3-00c04fd930c9 - Domain
                //f30e3bc2-9ff0-11d1-b603-0000f80367c1 - GPC

                if (mappedPrincipal.PrincipalName.Contains("Local System"))
                    continue;

                //We have a principal and we've successfully resolved the object. Lets process stuff!

                //Convert our right to an ActiveDirectoryRight enum object, and then to a string
                var adRight = (ActiveDirectoryRights) Enum.ToObject(typeof(ActiveDirectoryRights), qAce.AccessMask);
                var adRightString = adRight.ToString();
                   
                //Get the ACE for our right
                var ace = qAce as ObjectAce;
                var guid = ace != null ? ace.ObjectAceType.ToString() : "";
                var toContinue = false;

                //Figure out if we need more processing by matching the right name + guid together
                toContinue |= (adRightString.Contains("WriteDacl") || adRightString.Contains("WriteOwner"));
                if (adRightString.Contains("GenericWrite") || adRightString.Contains("GenericAll"))
                    toContinue |= ("00000000-0000-0000-0000-000000000000".Equals(guid) || guid.Equals("") || toContinue);

                if (adRightString.Contains("ExtendedRight"))
                {
                    toContinue |= (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("") ||
                                   guid.Equals("00299570-246d-11d0-a768-00aa006e0529") || toContinue);

                    //DCSync rights
                    toContinue |= (guid.Equals("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") ||
                                   guid.Equals("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") || toContinue);
                }

                if (adRightString.Contains("WriteProperty"))
                    toContinue |= (guid.Equals("00000000-0000-0000-0000-000000000000") ||
                                   guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2") ||
                                   guid.Equals("bf9679a8-0de6-11d0-a285-00aa003049e2") ||
                                   guid.Equals("f30e3bc1-9ff0-11d1-b603-0000f80367c1") || toContinue);

                var inheritedObjectType = ace != null ? ace.InheritedObjectAceType.ToString() : "00000000-0000-0000-0000-000000000000";
                var isInherited = false;

                //Check if the ACE applies to us. This can either be because the ACE applies to any object type (the null guid)
                //or because the ACE replies to our object type (which is different per entry type).
                switch (entryType)
                {
                    case "user":
                        isInherited = inheritedObjectType.Equals("00000000-0000-0000-0000-000000000000") ||
                                     inheritedObjectType.Equals("bf967aba-0de6-11d0-a285-00aa003049e2");
                        break;
                    case "group":
                        isInherited = inheritedObjectType.Equals("00000000-0000-0000-0000-000000000000") ||
                                     inheritedObjectType.Equals("bf967a9c-0de6-11d0-a285-00aa003049e2");
                        break;
                    case "domain":
                        isInherited = inheritedObjectType.Equals("00000000-0000-0000-0000-000000000000") ||
                                     inheritedObjectType.Equals("19195a5a-6da0-11d0-afd3-00c04fd930c9");
                        break;
                    case "gpo":
                        isInherited = inheritedObjectType.Equals("00000000-0000-0000-0000-000000000000") ||
                                      inheritedObjectType.Equals("f30e3bc2-9ff0-11d1-b603-0000f80367c1");
                        break;
                }
                
                //Special case used for example by Exchange: the ACE is inherited but also applies to the object it is set on
                // this is verified by looking if this ACE is not inherited, and is not an inherit-only ACE
                if (!isInherited && !((ace.AceFlags & AceFlags.InheritOnly) == AceFlags.InheritOnly) && !((ace.AceFlags & AceFlags.Inherited) == AceFlags.Inherited))
                {
                    //If these conditions hold the ACE applies to this object anyway
                    isInherited = true;
                }
                    
                if (!toContinue || !isInherited)
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
                        //Though it doesn't make sense privilege wise, the Exchange reset password permissions also apply to the
                        //domain object. We need to catch this properly otherwise "All" access is assumed, which is incorrect
                        case "00299570-246d-11d0-a768-00aa006e0529":
                            aceType = "User-Force-Change-Password";
                            break;
                        default:
                            aceType = "All";
                            break;
                    }
                }

                //If we have either of the DCSync rights, store it in a temporary object and continue.
                //We need both rights for either right to mean anything to us
                if (aceType != null && entryType.Equals("domain") && (aceType.Equals("DS-Replication-Get-Changes-All") ||
                                        aceType.Equals("DS-Replication-Get-Changes")))
                {
                    if (!_syncers.TryGetValue(mappedPrincipal.PrincipalName, out var sync))
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

                if (aceType != null && entryType.Equals("domain") && aceType.Equals("All"))
                {
                    if (!_syncers.TryGetValue(mappedPrincipal.PrincipalName, out var sync))
                    {
                        sync = new DcSync
                        {
                            Domain = entryDisplayName,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType
                        };
                    }

                    sync.GetChangesAll = true;
                    sync.GetChanges = true;

                    _syncers.AddOrUpdate(mappedPrincipal.PrincipalName, sync, (key, oldVar) => sync);
                }

                if (aceType != null && entryType.Equals("domain") && adRightString.Contains("GenericAll"))
                {
                    if (!_syncers.TryGetValue(mappedPrincipal.PrincipalName, out var sync))
                    {
                        sync = new DcSync
                        {
                            Domain = entryDisplayName,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType
                        };
                    }

                    sync.GetChangesAll = true;
                    sync.GetChanges = true;

                    _syncers.AddOrUpdate(mappedPrincipal.PrincipalName, sync, (key, oldVar) => sync);
                }

                //Return ACL objects based on rights + guid combos

                if (adRightString.Contains("GenericAll"))
                {
                    yield return new ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        ObjectType = entryType,
                        ObjectName = entryDisplayName,
                        RightName = "GenericAll",
                        Qualifier = qAce.AceQualifier.ToString(),
                        ObjectGuid = entryGuid
                    };
                }

                if (adRightString.Contains("GenericWrite") && !entryType.Equals("domain"))
                {
                    yield return new ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        ObjectType = entryType,
                        ObjectName = entryDisplayName,
                        RightName = "GenericWrite",
                        Qualifier = qAce.AceQualifier.ToString(),
                        ObjectGuid = entryGuid
                    };
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    yield return new ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        ObjectType = entryType,
                        ObjectName = entryDisplayName,
                        RightName = "WriteOwner",
                        Qualifier = qAce.AceQualifier.ToString(),
                        ObjectGuid = entryGuid
                    };
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    yield return new ACL
                    {
                        AceType = "",
                        Inherited = qAce.IsInherited,
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        ObjectType = entryType,
                        ObjectName = entryDisplayName,
                        RightName = "WriteDacl",
                        Qualifier = qAce.AceQualifier.ToString(),
                        ObjectGuid = entryGuid
                    };
                }

                if (adRightString.Contains("WriteProperty"))
                {
                    if (guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2") && entryType=="group")
                    {
                        yield return new ACL
                        {
                            AceType = "Member",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            ObjectType = entryType,
                            ObjectName = entryDisplayName,
                            RightName = "WriteProperty",
                            Qualifier = qAce.AceQualifier.ToString(),
                            ObjectGuid = entryGuid
                        };
                    }
                    //else if (guid.Equals("f30e3bc1-9ff0-11d1-b603-0000f80367c1") && entryType.Equals("gpo"))
                    //{
                    //    yield return new ACL
                    //    {
                    //        AceType = "GPC-File-Sys-Path",
                    //        Inherited = qAce.IsInherited,
                    //        PrincipalName = mappedPrincipal.PrincipalName,
                    //        PrincipalType = mappedPrincipal.ObjectType,
                    //        ObjectType = entryType,
                    //        ObjectName = entryDisplayName,
                    //        RightName = "WriteProperty",
                    //        Qualifier = qAce.AceQualifier.ToString(),
                    //        ObjectGuid = entryGuid
                    //    };
                    //}
                }

                if (adRightString.Contains("ExtendedRight"))
                {
                    if (guid.Equals("00299570-246d-11d0-a768-00aa006e0529") && entryType.Equals("user"))
                    {
                        yield return new ACL
                        {
                            AceType = "User-Force-Change-Password",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            ObjectType = entryType,
                            ObjectName = entryDisplayName,
                            RightName = "ExtendedRight",
                            Qualifier = qAce.AceQualifier.ToString(),
                            ObjectGuid = entryGuid
                        };
                    }
                    else if (guid.Equals("00000000-0000-0000-0000-000000000000"))
                    {
                        yield return new ACL
                        {
                            AceType = "All",
                            Inherited = qAce.IsInherited,
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            ObjectType = entryType,
                            ObjectName = entryDisplayName,
                            RightName = "ExtendedRight",
                            Qualifier = qAce.AceQualifier.ToString(),
                            ObjectGuid = entryGuid
                        };
                    }
                }
            }
        }
    }
}
