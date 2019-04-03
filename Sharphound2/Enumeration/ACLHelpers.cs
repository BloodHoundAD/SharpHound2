using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
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
        private static ConcurrentDictionary<string, string> _baseGuids;
        private static readonly string AllGuid = "00000000-0000-0000-0000-000000000000";


        public static void Init()
        {
            _utils = Utils.Instance;
            _nullSids = new ConcurrentDictionary<string, byte>();
            _guidMap = new ConcurrentDictionary<string, string>();
            _baseGuids = new ConcurrentDictionary<string, string>();
            _baseGuids.TryAdd("user", "bf967aba-0de6-11d0-a285-00aa003049e2");
            _baseGuids.TryAdd("computer", "bf967a86-0de6-11d0-a285-00aa003049e2");
            _baseGuids.TryAdd("group", "bf967a9c-0de6-11d0-a285-00aa003049e2");
            _baseGuids.TryAdd("domain", "19195a5a-6da0-11d0-afd3-00c04fd930c9");
            _baseGuids.TryAdd("gpo", "f30e3bc2-9ff0-11d1-b603-0000f80367c1");
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

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Domain obj)
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

            var newDescriptor = new ActiveDirectorySecurity();
            newDescriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
            var owner = GetAclOwner(newDescriptor, domainName);

            if (owner != null)
            {
                aces.Add(new ACL
                {
                    AceType = "",
                    RightName = "Owner",
                    PrincipalName = owner.PrincipalName,
                    PrincipalType = owner.ObjectType
                });
            }

            foreach (ActiveDirectoryAccessRule ace in newDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                //Ignore null aces
                if (ace == null)
                    continue;

                //Ignore Deny aces
                if (!ace.AccessControlType.Equals(AccessControlType.Allow))
                    continue;

                //Resolve the principal in the ACE
                var principal = GetAcePrincipal(ace, domainName);

                //If its null, we don't care so move on
                if (principal == null)
                    continue;

                //Check if our ACE applies through inheritance rules
                if (!CheckAceInheritanceRules(ace, resolved.ObjectType))
                    continue;

                //Interesting Domain ACEs - GenericAll, WriteDacl, WriteOwner, Replication Rights, AllExtendedRights
                var rights = ace.ActiveDirectoryRights;
                var objectAceType = ace.ObjectType.ToString();
                
                if (rights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (objectAceType == AllGuid || objectAceType == "")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            RightName = "GenericAll",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }
                    //GenericAll includes every other flag, so continue here so we don't duplicate privs
                    continue;
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteDacl))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "WriteDacl",
                        PrincipalName = principal.PrincipalName,
                        PrincipalType = principal.ObjectType
                    });
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteOwner))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "WriteOwner",
                        PrincipalName = principal.PrincipalName,
                        PrincipalType = principal.ObjectType
                    });
                }

                if (rights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                {
                    if (objectAceType == "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "GetChanges",
                            RightName = "ExtendedRight",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }else if (objectAceType == "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "GetChangesAll",
                            RightName = "ExtendedRight",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }else if (objectAceType == AllGuid || objectAceType == "")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "All",
                            RightName = "ExtendedRight",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }
                }
            }

            obj.Aces = aces.Distinct().ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Group obj)
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

            var newDescriptor = new ActiveDirectorySecurity();
            newDescriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
            var owner = GetAclOwner(newDescriptor, domainName);

            if (owner != null)
            {
                aces.Add(new ACL
                {
                    AceType = "",
                    RightName = "Owner",
                    PrincipalName = owner.PrincipalName,
                    PrincipalType = owner.ObjectType
                });
            }


            foreach (ActiveDirectoryAccessRule ace in newDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                //Ignore null aces
                if (ace == null)
                    continue;

                //Ignore Deny aces
                if (!ace.AccessControlType.Equals(AccessControlType.Allow))
                    continue;

                //Resolve the principal in the ACE
                var principal = GetAcePrincipal(ace, domainName);

                //If its null, we don't care so move on
                if (principal == null)
                    continue;

                //Check if our ACE applies through inheritance rules
                if (!CheckAceInheritanceRules(ace, resolved.ObjectType))
                    continue;

                //Interesting Group ACEs - GenericAll, WriteDacl, WriteOwner, GenericWrite, AddMember
                var rights = ace.ActiveDirectoryRights;

                var objectAceType = ace.ObjectType.ToString();
                
                if (rights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (objectAceType == AllGuid || objectAceType == "")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            RightName = "GenericAll",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }
                    //GenericAll includes every other flag, so continue here so we don't duplicate privs
                    continue;
                }

                if (rights.HasFlag(ActiveDirectoryRights.GenericWrite)
                    || rights.HasFlag(ActiveDirectoryRights.WriteProperty))
                {
                    //GenericWrite encapsulates WriteProperty
                    if (rights.HasFlag(ActiveDirectoryRights.GenericWrite) &&
                        (objectAceType == AllGuid || objectAceType == ""))
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            RightName = "GenericWrite",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }
                    else if (rights.HasFlag(ActiveDirectoryRights.WriteProperty))
                    {
                        if (objectAceType == "bf9679c0-0de6-11d0-a285-00aa003049e2")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "AddMember",
                                RightName = "WriteProperty",
                                PrincipalName = principal.PrincipalName,
                                PrincipalType = principal.ObjectType
                            });
                        }else if (objectAceType == AllGuid || objectAceType == "")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "",
                                RightName = "GenericWrite",
                                PrincipalName = principal.PrincipalName,
                                PrincipalType = principal.ObjectType
                            });
                        }
                    }
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteDacl))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "WriteDacl",
                        PrincipalName = principal.PrincipalName,
                        PrincipalType = principal.ObjectType
                    });
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteOwner))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "WriteOwner",
                        PrincipalName = principal.PrincipalName,
                        PrincipalType = principal.ObjectType
                    });
                }
            }

            obj.Aces = aces.Distinct().ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref User obj)
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

            var newDescriptor = new ActiveDirectorySecurity();
            newDescriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
            var owner = GetAclOwner(newDescriptor, domainName);

            if (owner != null)
            {
                aces.Add(new ACL
                {
                    AceType = "",
                    RightName = "Owner",
                    PrincipalName = owner.PrincipalName,
                    PrincipalType = owner.ObjectType
                });
            }


            foreach (ActiveDirectoryAccessRule ace in newDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                //Ignore null aces
                if (ace == null)
                    continue;

                //Ignore Deny aces
                if (!ace.AccessControlType.Equals(AccessControlType.Allow))
                    continue;

                //Resolve the principal in the ACE
                var principal = GetAcePrincipal(ace, domainName);

                //If its null, we don't care so move on
                if (principal == null)
                    continue;

                //Check if our ACE applies through inheritance rules
                if (!CheckAceInheritanceRules(ace, resolved.ObjectType))
                    continue;

                //Interesting User ACEs - GenericAll, WriteDacl, WriteOwner, GenericWrite, ForceChangePassword
                var rights = ace.ActiveDirectoryRights;
                var objectAceType = ace.ObjectType.ToString();

                if (rights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (objectAceType == AllGuid || objectAceType == "")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            RightName = "GenericAll",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }
                    //GenericAll includes every other flag, so continue here so we don't duplicate privs
                    continue;
                }

                if (rights.HasFlag(ActiveDirectoryRights.GenericWrite)
                    || rights.HasFlag(ActiveDirectoryRights.WriteProperty))
                {
                    //GenericWrite encapsulates WriteProperty
                    if (rights.HasFlag(ActiveDirectoryRights.GenericWrite) &&
                        (objectAceType == AllGuid || objectAceType == ""))
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            RightName = "GenericWrite",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }
                    else if (rights.HasFlag(ActiveDirectoryRights.WriteProperty))
                    {
                        if (objectAceType == AllGuid || objectAceType == "")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "",
                                RightName = "GenericWrite",
                                PrincipalName = principal.PrincipalName,
                                PrincipalType = principal.ObjectType
                            });
                        }
                    }
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteDacl))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "WriteDacl",
                        PrincipalName = principal.PrincipalName,
                        PrincipalType = principal.ObjectType
                    });
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteOwner))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "WriteOwner",
                        PrincipalName = principal.PrincipalName,
                        PrincipalType = principal.ObjectType
                    });
                }

                if (rights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                {
                    if (objectAceType == "00299570-246d-11d0-a768-00aa006e0529")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "User-Force-Change-Password",
                            RightName = "ExtendedRight",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }else if (objectAceType == AllGuid || objectAceType == "")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "All",
                            RightName = "ExtendedRight",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }
                }
            }

            obj.Aces = aces.Distinct().ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Gpo obj)
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

            var newDescriptor = new ActiveDirectorySecurity();
            newDescriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
            var owner = GetAclOwner(newDescriptor, domainName);

            if (owner != null)
            {
                aces.Add(new ACL
                {
                    AceType = "",
                    RightName = "Owner",
                    PrincipalName = owner.PrincipalName,
                    PrincipalType = owner.ObjectType
                });
            }


            foreach (ActiveDirectoryAccessRule ace in newDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                //Ignore null aces
                if (ace == null)
                    continue;

                //Ignore Deny aces
                if (!ace.AccessControlType.Equals(AccessControlType.Allow))
                    continue;

                //Resolve the principal in the ACE
                var principal = GetAcePrincipal(ace, domainName);

                //If its null, we don't care so move on
                if (principal == null)
                    continue;

                //Check if our ACE applies through inheritance rules
                if (!CheckAceInheritanceRules(ace, resolved.ObjectType))
                    continue;

                //Interesting GPO ACEs - GenericAll, WriteDacl, WriteOwner
                var rights = ace.ActiveDirectoryRights;
                var objectAceType = ace.ObjectType.ToString();
                
                if (rights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (objectAceType == AllGuid || objectAceType == "")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            RightName = "GenericAll",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }
                    //GenericAll includes every other flag, so continue here so we don't duplicate privs
                    continue;
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteDacl))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "WriteDacl",
                        PrincipalName = principal.PrincipalName,
                        PrincipalType = principal.ObjectType
                    });
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteOwner))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "WriteOwner",
                        PrincipalName = principal.PrincipalName,
                        PrincipalType = principal.ObjectType
                    });
                }
            }

            obj.Aces = aces.Distinct().ToArray();
        }

        public static void GetObjectAces(SearchResultEntry entry, ResolvedEntry resolved, ref Computer obj)
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

            var newDescriptor = new ActiveDirectorySecurity();
            newDescriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
            var owner = GetAclOwner(newDescriptor, domainName);

            if (owner != null)
            {
                aces.Add(new ACL
                {
                    AceType = "",
                    RightName = "Owner",
                    PrincipalName = owner.PrincipalName,
                    PrincipalType = owner.ObjectType
                });
            }


            foreach (ActiveDirectoryAccessRule ace in newDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                //Ignore null aces
                if (ace == null)
                    continue;

                //Ignore Deny aces
                if (!ace.AccessControlType.Equals(AccessControlType.Allow))
                    continue;

                //Resolve the principal in the ACE
                var principal = GetAcePrincipal(ace, domainName);

                //If its null, we don't care so move on
                if (principal == null)
                    continue;

                //Check if our ACE applies through inheritance rules
                if (!CheckAceInheritanceRules(ace, resolved.ObjectType))
                    continue;

                //Interesting Computer ACEs - GenericAll, WriteDacl, GenericWrite, WriteProperty (AllowedToAct), WriteOwner, ExtendedRight (LAPS)
                var rights = ace.ActiveDirectoryRights;
                var objectAceType = ace.ObjectType.ToString();

                _guidMap.TryGetValue(objectAceType, out var mappedGuid);

                if (rights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (objectAceType == AllGuid || objectAceType == "")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            RightName = "GenericAll",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }else if (mappedGuid != null && mappedGuid == "ms-Mcs-AdmPwd")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            RightName = "ReadLAPSPassword",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }
                    //GenericAll includes every other flag, so continue here so we don't duplicate privs
                    continue;
                }

                if (rights.HasFlag(ActiveDirectoryRights.GenericWrite)
                    || rights.HasFlag(ActiveDirectoryRights.WriteProperty))
                {
                    //GenericWrite encapsulates WriteProperty
                    if (rights.HasFlag(ActiveDirectoryRights.GenericWrite) &&
                        (objectAceType == AllGuid || objectAceType == ""))
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            RightName = "GenericWrite",
                            PrincipalName = principal.PrincipalName,
                            PrincipalType = principal.ObjectType
                        });
                    }
                    else if (rights.HasFlag(ActiveDirectoryRights.WriteProperty))
                    {
                        if (objectAceType == AllGuid || objectAceType == "")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "",
                                RightName = "GenericWrite",
                                PrincipalName = principal.PrincipalName,
                                PrincipalType = principal.ObjectType
                            });
                        }else if (objectAceType == "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "AllowedToAct",
                                PrincipalName = principal.PrincipalName,
                                PrincipalType = principal.ObjectType,
                                RightName = "WriteProperty"
                            });
                        }
                    }
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteDacl))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "WriteDacl",
                        PrincipalName = principal.PrincipalName,
                        PrincipalType = principal.ObjectType
                    });
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteOwner))
                {
                    aces.Add(new ACL
                    {
                        AceType = "",
                        RightName = "WriteOwner",
                        PrincipalName = principal.PrincipalName,
                        PrincipalType = principal.ObjectType
                    });
                }

                if (rights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                {
                    if (entry.GetProp("ms-mcs-admpwdexpirationtime") != null)
                    {
                        if (mappedGuid != null && mappedGuid == "ms-Mcs-AdmPwd")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "",
                                RightName = "ReadLAPSPassword",
                                PrincipalName = principal.PrincipalName,
                                PrincipalType = principal.ObjectType
                            });
                        }else if (objectAceType == AllGuid || objectAceType == "")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "All",
                                RightName = "ExtendedRight",
                                PrincipalName = principal.PrincipalName,
                                PrincipalType = principal.ObjectType
                            });
                        }
                    }
                }
            }

            obj.Aces = aces.Distinct().ToArray();
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

        private static MappedPrincipal GetAclOwner(ActiveDirectorySecurity acl, string domainName)
        {
            var sid = acl.GetOwner(typeof(SecurityIdentifier)).Value;

            //Filter Local System/Creator Owner/Principal Self
            if (sid == "S-1-5-18" || sid == "S-1-3-0" || sid == "S-1-5-10")
            {
                return null;
            }

            if (!_nullSids.TryGetValue(sid, out _))
            {
                //Check if its a common SID
                if (!MappedPrincipal.GetCommon(sid, out var owner))
                {
                    //Resolve the sid manually if we still dont have it
                    var ownerDomain = _utils.SidToDomainName(sid) ?? domainName;
                    owner = _utils.UnknownSidTypeToDisplay(sid, ownerDomain, Props);
                }
                else
                {
                    owner.PrincipalName = $"{owner.PrincipalName}@{domainName}";
                }

                //We'll cache SIDs we've failed to resolve previously so we dont keep trying
                if (owner == null)
                {
                    _nullSids.TryAdd(sid, new byte());
                }

                return owner;
            }

            return null;
        }

        private static MappedPrincipal GetAcePrincipal(ActiveDirectoryAccessRule rule, string domainName)
        {
            var sid = rule.IdentityReference.Value;

            //Filter Local System/Creator Owner/Principal Self
            if (sid == "S-1-5-18" || sid == "S-1-3-0" || sid == "S-1-5-10")
            {
                return null;
            }

            if (!_nullSids.TryGetValue(sid, out _))
            {
                //Check if its a common SID
                if (!MappedPrincipal.GetCommon(sid, out var principal))
                {
                    //Resolve the sid manually if we still don't have it
                    var ownerDomain = _utils.SidToDomainName(sid) ?? domainName;
                    principal = _utils.UnknownSidTypeToDisplay(sid, ownerDomain, Props);
                }
                else
                {
                    if (sid == "S-1-5-9")
                    {
                        var dObj = _utils.GetForest(domainName);
                        var d = dObj == null ? domainName : dObj.RootDomain.Name;
                        principal.PrincipalName = $"ENTERPRISE DOMAIN CONTROLLERS@{d}".ToUpper();
                    }
                    else
                    {
                        principal.PrincipalName = $"{principal.PrincipalName}@{domainName}";
                    }
                }

                //We'll cache SIDs we've failed to resolve previously so we dont keep trying
                if (principal == null)
                {
                    _nullSids.TryAdd(sid, new byte());
                }

                return principal;
            }

            return null;
        }

        private static bool CheckAceInheritanceRules(ActiveDirectoryAccessRule ace, string baseType)
        {
            //First case - the ACE is inherited
            if (ace.IsInherited)
            {
                // Grab the guid for our object the ace is applied too
                if (!_baseGuids.TryGetValue(baseType, out var baseGuid))
                    return false;
                
                var inheritedType = ace.InheritedObjectType.ToString();
                //Compare the InheritedObjectType for the ACE to either the guid for all objects or our base object's GUID
                return inheritedType == AllGuid || inheritedType == baseGuid;
            }

            //Second case - the ACE is not inherited and applied directly to the object
            //If the ACE is marked as InheritOnly, it doesn't apply to the object
            if ((ace.PropagationFlags & PropagationFlags.InheritOnly) != 0)
            {
                return false;
            }

            // The ACE is not inherited, and applies to the object
            return true;
        }
    }
}
