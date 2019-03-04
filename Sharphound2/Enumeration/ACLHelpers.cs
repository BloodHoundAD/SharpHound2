using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.AccessControl;
using Sharphound2.JsonObjects;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace Sharphound2.Enumeration
{
    internal static class AclHelpers
    {
        private static Utils _utils;
        private static ConcurrentDictionary<string, byte> _nullSids;
        private static readonly string[] Props = { "distinguishedname", "samaccounttype", "samaccountname", "dnshostname" };
        private static ConcurrentDictionary<string, string> _guidMap;

        public static void Init()
        {
            _utils = Utils.Instance;
            _nullSids = new ConcurrentDictionary<string, byte>();
            _guidMap = new ConcurrentDictionary<string, string>();
        }

        internal static void BuildGuidCache()
        {
            var forest = _utils.GetForest();
            if (forest == null)
                return;


            var schema = forest.Schema.Name;

            foreach (var entry in _utils.DoSearch("(schemaIDGUID=*)", SearchScope.Subtree, new[] { "schemaidguid", "name" }, adsPath: schema))
            {
                var name = entry.GetProp("name");
                var guid = new Guid(entry.GetPropBytes("schemaidguid")).ToString();
                _guidMap.TryAdd(guid, name);
            }
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Domain u)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ACL))
                return;

            var aces = new List<ACL>();
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
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "Owner",
                        PrincipalName = owner.PrincipalName,
                        PrincipalType = owner.ObjectType
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

                if (!qAce.AceQualifier.Equals(AceQualifier.AccessAllowed))
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
                    if (mappedPrincipal.PrincipalName == "ENTERPRISE DOMAIN CONTROLLERS")
                    {
                        var dObj = _utils.GetForest(domainName);
                        var d = dObj == null ? domainName : dObj.RootDomain.Name;
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{d}".ToUpper();
                    }
                    else
                    {
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{domainName}".ToUpper();
                    }
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

                var flags = ace == null ? AceFlags.None : ace.AceFlags;
                var isInherited = (flags & AceFlags.InheritOnly) != 0;

                isInherited = isInherited && (inheritedObjectType == "00000000-0000-0000-0000-000000000000" ||
                    inheritedObjectType == "19195a5a-6da0-11d0-afd3-00c04fd930c9");

                //Special case used for example by Exchange: the ACE is inherited but also applies to the object it is set on
                // this is verified by looking if this ACE is not inherited, and is not an inherit-only ACE
                if (!isInherited && (flags & AceFlags.InheritOnly) != AceFlags.InheritOnly && (flags & AceFlags.Inherited) != AceFlags.Inherited)
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
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "GenericAll"
                    });
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteOwner"
                    });
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteDacl"
                    });
                }

                if (adRightString.Contains("ExtendedRight"))
                {
                    if (guid.Equals("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"))
                    {
                        aces.Add(new ACL
                        {
                            AceType = "GetChanges",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "ExtendedRight"
                        });
                    }else if (guid.Equals("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"))
                    {
                        aces.Add(new ACL
                        {
                            AceType = "GetChangesAll",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "ExtendedRight"
                        });
                    }
                    else
                    {
                        aces.Add(new ACL
                        {
                            AceType = "All",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "ExtendedRight"
                        });
                    }

                }
            }

            u.Aces = aces.Distinct().ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Group u)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ACL))
                return;

            var aces = new List<ACL>();
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
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "Owner",
                        PrincipalName = owner.PrincipalName,
                        PrincipalType = owner.ObjectType
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

                if (!qAce.AceQualifier.Equals(AceQualifier.AccessAllowed))
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
                    if (mappedPrincipal.PrincipalName == "ENTERPRISE DOMAIN CONTROLLERS")
                    {
                        var dObj = _utils.GetForest(domainName);
                        var d = dObj == null ? domainName : dObj.RootDomain.Name;
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{d}".ToUpper();
                    }
                    else
                    {
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{domainName}".ToUpper();
                    }
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

                var flags = ace == null ? AceFlags.None : ace.AceFlags;
                var isInherited = (flags & AceFlags.InheritOnly) != 0;

                isInherited = isInherited && (inheritedObjectType == "00000000-0000-0000-0000-000000000000" ||
                                              inheritedObjectType == "bf967a9c-0de6-11d0-a285-00aa003049e2");

                //Special case used for example by Exchange: the ACE is inherited but also applies to the object it is set on
                // this is verified by looking if this ACE is not inherited, and is not an inherit-only ACE
                if (!isInherited && (flags & AceFlags.InheritOnly) != AceFlags.InheritOnly && (flags & AceFlags.Inherited) != AceFlags.Inherited)
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
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "GenericAll"
                    });
                }

                if (adRightString.Contains("GenericWrite"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "GenericWrite"
                    });
                }

                if (adRightString.Contains("WriteProperty"))
                {
                    if (guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2"))
                    {
                        aces.Add(new ACL
                        {
                            AceType = "Member",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "WriteProperty"
                        });
                    }
                    else
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "GenericWrite"
                        });
                    }
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteOwner"
                    });
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteDacl"
                    });
                }
            }

            u.Aces = aces.Distinct().ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref User u)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ACL))
                return;

            var aces = new List<ACL>();
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
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "Owner",
                        PrincipalName = owner.PrincipalName,
                        PrincipalType = owner.ObjectType
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

                if (!qAce.AceQualifier.Equals(AceQualifier.AccessAllowed))
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
                    if (mappedPrincipal.PrincipalName == "ENTERPRISE DOMAIN CONTROLLERS")
                    {
                        var dObj = _utils.GetForest(domainName);
                        var d = dObj == null ? domainName : dObj.RootDomain.Name;
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{d}".ToUpper();
                    }
                    else
                    {
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{domainName}".ToUpper();
                    }
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


                var flags = ace == null ? AceFlags.None : ace.AceFlags;
                var isInherited = (flags & AceFlags.InheritOnly) != 0;

                isInherited = isInherited && (inheritedObjectType == "00000000-0000-0000-0000-000000000000" ||
                                              inheritedObjectType == "bf967aba-0de6-11d0-a285-00aa003049e2");

                //Special case used for example by Exchange: the ACE is inherited but also applies to the object it is set on
                // this is verified by looking if this ACE is not inherited, and is not an inherit-only ACE
                if (!isInherited && (flags & AceFlags.InheritOnly) != AceFlags.InheritOnly && (flags & AceFlags.Inherited) != AceFlags.Inherited)
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
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "GenericAll"
                    });
                }

                if (adRightString.Contains("GenericWrite") || adRightString.Contains("WriteProperty"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "GenericWrite"
                    });
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteOwner"
                    });
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteDacl"
                    });
                }

                if (adRightString.Contains("ExtendedRight"))
                {
                    if (guid.Equals("00299570-246d-11d0-a768-00aa006e0529"))
                    {
                        aces.Add(new ACL
                        {
                            AceType = "User-Force-Change-Password",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "ExtendedRight"
                        });
                    }
                    else if (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals(""))
                    {
                        aces.Add(new ACL
                        {
                            AceType = "All",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "ExtendedRight"
                        });
                    }
                }
            }

            u.Aces = aces.Distinct().ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Gpo g)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ACL))
                return;

            var aces = new List<ACL>();
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
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "Owner",
                        PrincipalName = owner.PrincipalName,
                        PrincipalType = owner.ObjectType
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

                if (!qAce.AceQualifier.Equals(AceQualifier.AccessAllowed))
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
                    if (mappedPrincipal.PrincipalName == "ENTERPRISE DOMAIN CONTROLLERS")
                    {
                        var dObj = _utils.GetForest(domainName);
                        var d = dObj == null ? domainName : dObj.RootDomain.Name;
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{d}".ToUpper();
                    }
                    else
                    {
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{domainName}".ToUpper();
                    }
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

                var flags = ace == null ? AceFlags.None : ace.AceFlags;
                var isInherited = (flags & AceFlags.InheritOnly) != 0;

                isInherited = isInherited && (inheritedObjectType == "00000000-0000-0000-0000-000000000000" ||
                                              inheritedObjectType == "f30e3bc2-9ff0-11d1-b603-0000f80367c1");


                //Special case used for example by Exchange: the ACE is inherited but also applies to the object it is set on
                // this is verified by looking if this ACE is not inherited, and is not an inherit-only ACE
                if (!isInherited && (flags & AceFlags.InheritOnly) != AceFlags.InheritOnly && (flags & AceFlags.Inherited) != AceFlags.Inherited)
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
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "GenericAll"
                    });
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteOwner"
                    });
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteDacl"
                    });
                }
            }

            g.Aces = aces.Distinct().ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Computer g)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ACL))
                return;
            
            var aces = new List<ACL>();
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
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "Owner",
                        PrincipalName = owner.PrincipalName,
                        PrincipalType = owner.ObjectType
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

                if (!qAce.AceQualifier.Equals(AceQualifier.AccessAllowed))
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
                    if (mappedPrincipal.PrincipalName == "ENTERPRISE DOMAIN CONTROLLERS")
                    {
                        var dObj = _utils.GetForest(domainName);
                        var d = dObj == null ? domainName : dObj.RootDomain.Name;
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{d}".ToUpper();
                    }
                    else
                    {
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{domainName}".ToUpper();
                    }
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

                var flags = ace == null ? AceFlags.None : ace.AceFlags;
                var isInherited = (flags & AceFlags.InheritOnly) != 0;

                isInherited = isInherited && (inheritedObjectType == "00000000-0000-0000-0000-000000000000" ||
                                              inheritedObjectType == "bf967a86-0de6-11d0-a285-00aa003049e2");

                //Special case used for example by Exchange: the ACE is inherited but also applies to the object it is set on
                // this is verified by looking if this ACE is not inherited, and is not an inherit-only ACE
                if (!isInherited && (flags & AceFlags.InheritOnly) != AceFlags.InheritOnly && (flags & AceFlags.Inherited) != AceFlags.Inherited)
                {
                    //If these conditions hold the ACE applies to this object anyway
                    isInherited = true;
                }

                if (!isInherited)
                    continue;

                var toContinue = false;

                _guidMap.TryGetValue(guid, out var mappedGuid);

                //Interesting Computer ACEs - GenericAll, WriteDacl, WriteOwner, ExtendedRight
                toContinue |= adRightString.Contains("WriteDacl") ||
                               adRightString.Contains("WriteOwner");

                if (adRightString.Contains("GenericAll"))
                {
                    toContinue |= "00000000-0000-0000-0000-000000000000".Equals(guid) || guid.Equals("") || toContinue;
                    toContinue |= mappedGuid != null && mappedGuid == "ms-Mcs-AdmPwd" || toContinue;
                }

                if (adRightString.Contains("ExtendedRight"))
                {
                    toContinue |= guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("") || toContinue;
                    toContinue |= mappedGuid != null && mappedGuid == "ms-Mcs-AdmPwd" || toContinue;
                }

                if (adRightString.Contains("WriteProperty"))
                {
                    toContinue |= "00000000-0000-0000-0000-000000000000".Equals(guid) || guid.Equals("") || toContinue;
                    toContinue |= "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79".Equals(guid) || toContinue;
                }

                if (!toContinue)
                    continue;

                if (adRightString.Contains("GenericAll"))
                {
                    if (mappedGuid == "ms-Mcs-AdmPwd")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "ReadLAPSPassword"
                        });
                    }
                    else
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "GenericAll"
                        });
                    }
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteOwner"
                    });
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteDacl"
                    });
                }

                if (adRightString.Contains("WriteProperty"))
                {
                    if (guid.Equals("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"))
                    {
                        aces.Add(new ACL
                        {
                            AceType = "AllowedToAct",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "WriteProperty"
                        });
                    }
                    else
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "GenericWrite"
                        });
                    }
                }

                if (adRightString.Contains("ExtendedRight") && entry.GetProp("ms-mcs-admpwdexpirationtime") != null)
                {
                    if (mappedGuid == "ms-Mcs-AdmPwd")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "ReadLAPSPassword"
                        });
                    }
                    else
                    {
                        aces.Add(new ACL
                        {
                            AceType = "All",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "ExtendedRight"
                        });
                    }
                }
            }

            g.Aces = aces.Distinct().ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Ou g)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ACL))
                return;
            
            var aces = new List<ACL>();
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
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "Owner",
                        PrincipalName = owner.PrincipalName,
                        PrincipalType = owner.ObjectType
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
                    if (mappedPrincipal.PrincipalName == "ENTERPRISE DOMAIN CONTROLLERS")
                    {
                        var dObj = _utils.GetForest(domainName);
                        var d = dObj == null ? domainName : dObj.RootDomain.Name;
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{d}".ToUpper();
                    }
                    else
                    {
                        mappedPrincipal.PrincipalName = $"{mappedPrincipal.PrincipalName}@{domainName}".ToUpper();
                    }
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

                var flags = ace == null ? AceFlags.None : ace.AceFlags;
                var isInherited = (flags & AceFlags.InheritOnly) != 0;

                isInherited = isInherited && (inheritedObjectType == "00000000-0000-0000-0000-000000000000" ||
                                              inheritedObjectType == "bf967aa5-0de6-11d0-a285-00aa003049e2");

                //Special case used for example by Exchange: the ACE is inherited but also applies to the object it is set on
                // this is verified by looking if this ACE is not inherited, and is not an inherit-only ACE
                if (!isInherited && (flags & AceFlags.InheritOnly) != AceFlags.InheritOnly && (flags & AceFlags.Inherited) != AceFlags.Inherited)
                {
                    //If these conditions hold the ACE applies to this object anyway
                    isInherited = true;
                }

                if (!isInherited)
                    continue;

                var toContinue = false;

                _guidMap.TryGetValue(guid, out var mappedGuid);

                //Interesting OU ACEs - GenericAll, GenericWrite, WriteDacl, WriteOwner, 
                toContinue |= adRightString.Contains("WriteDacl") ||
                               adRightString.Contains("WriteOwner");

                if (adRightString.Contains("GenericAll"))
                {
                    toContinue |= "00000000-0000-0000-0000-000000000000".Equals(guid) || guid.Equals("") || toContinue;
                }
                if (adRightString.Contains("WriteProperty"))
                    toContinue |= guid.Equals("00000000-0000-0000-0000-000000000000") ||
                                  guid.Equals("f30e3bbe-9ff0-11d1-b603-0000f80367c1") || guid.Equals("") ||
                                  toContinue;

                if (!toContinue)
                    continue;

                if (adRightString.Contains("GenericAll"))
                {
                    if (mappedGuid == "ms-Mcs-AdmPwd")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "ReadLAPSPassword"
                        });
                    }
                    else
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "GenericAll"
                        });
                    }
                }

                if (adRightString.Contains("WriteOwner"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteOwner"
                    });
                }

                if (adRightString.Contains("WriteDacl"))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        PrincipalName = mappedPrincipal.PrincipalName,
                        PrincipalType = mappedPrincipal.ObjectType,
                        RightName = "WriteDacl"
                    });
                }

                if (adRightString.Contains("ExtendedRight"))
                {
                    if (mappedGuid == "ms-Mcs-AdmPwd")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "ReadLAPSPassword"
                        });
                    }
                    else
                    {
                        aces.Add(new ACL
                        {
                            AceType = "All",
                            PrincipalName = mappedPrincipal.PrincipalName,
                            PrincipalType = mappedPrincipal.ObjectType,
                            RightName = "ExtendedRight"
                        });
                    }
                }
            }

            g.Aces = aces.Distinct().ToArray();
        }
    }
}
