using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.XPath;
using Sharphound2.JsonObjects;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace Sharphound2.Enumeration
{
    internal class ApiFailedException : Exception {}

    internal class SystemDownException : Exception { }
    
    internal static class LocalGroupHelpers
    {
        private static Utils _utils;
        private static Sharphound.Options _options;
        private static readonly Regex KeyRegex = new Regex(@"(.+?)\s*=(.*)", RegexOptions.Compiled);
        private static readonly Regex MemberRegex = new Regex(@"\[Group Membership\](.*)(?:\[|$)", RegexOptions.Compiled | RegexOptions.Singleline);
        private static readonly Regex MemberLeftRegex = new Regex(@"(.*(?:S-1-5-32-544|S-1-5-32-555|S-1-5-32-562)__Members)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MemberRightRegex = new Regex(@"(S-1-5-32-544|S-1-5-32-555|S-1-5-32-562)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex ExtractRid = new Regex(@"S-1-5-32-([0-9]{3})", RegexOptions.Compiled);
        private static readonly string[] Props =
            {"samaccountname", "samaccounttype", "dnshostname", "serviceprincipalname", "distinguishedname"};

        private static readonly string[] GpoProps =
            {"samaccounttype", "dnshostname", "distinguishedname", "serviceprincipalname", "samaccountname"};

        private static readonly string[] GpLinkProps = {"distinguishedname"};

        private static readonly string[] AdminProps = {"samaccountname", "dnshostname", "distinguishedname", "samaccounttype"};

        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static byte[] _sidbytes;

        public static void Init(Sharphound.Options options)
        {
            _utils = Utils.Instance;
            _options = options;
            var sid = new SecurityIdentifier("S-1-5-32");
            _sidbytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(_sidbytes, 0);
        }

        private static SamEnumerationObject[] NetLocalGroupGetMembers(ResolvedEntry entry, int rid, out string machineSid)
        {
            Utils.Debug("Starting NetLocalGroupGetMembers");
            var server = new UNICODE_STRING(entry.BloodHoundDisplay);
            //Connect to the server with the proper access maskes. This gives us our server handle
            var obj = default(OBJECT_ATTRIBUTES);

            Utils.Debug("Starting SamConnect");
            var status = SamConnect(ref server, out var serverHandle,
                SamAccessMasks.SamServerLookupDomain |
                SamAccessMasks.SamServerConnect, ref obj);

            Utils.Debug($"SamConnect returned {status}");
            switch (status)
            {
                case NtStatus.StatusRpcServerUnavailable:
                    throw new SystemDownException();
                case NtStatus.StatusSuccess:
                    break;
                default:
                    throw new ApiFailedException();
            }

            Utils.Debug("Starting SamLookupDomainInSamServer");

            //Use SamLookupDomainInServer with the hostname to find the machine sid if possible
            try
            {
                var san = new UNICODE_STRING(entry.ComputerSamAccountName);
                SamLookupDomainInSamServer(serverHandle, ref san, out var temp);
                //This will throw an exception if we didn't actually find the alias
                machineSid = new SecurityIdentifier(temp).Value;
                SamFreeMemory(temp);
            }
            catch
            {
                machineSid = "DUMMYSTRINGSHOULDNOTMATCH";
            }

            Utils.Debug($"Resolved Machine Sid {machineSid}");

            Utils.Debug("Starting SamOpenDomain");
            //Open the domain for the S-1-5-32 (BUILTIN) alias
            status = SamOpenDomain(serverHandle, DomainAccessMask.Lookup, _sidbytes, out var domainHandle);
            Utils.Debug($"SamOpenDomain returned {status}");
            if (!status.Equals(NtStatus.StatusSuccess))
            {
                SamCloseHandle(serverHandle);
                throw new ApiFailedException();
            }

            Utils.Debug("Starting SamOpenAlias");
            //Open the alias for the desired RID
            status = SamOpenAlias(domainHandle, AliasOpenFlags.ListMembers, rid, out var aliasHandle);
            Utils.Debug($"SamOpenAlias returned {status}");
            if (!status.Equals(NtStatus.StatusSuccess))
            {
                SamCloseHandle(domainHandle);
                SamCloseHandle(serverHandle);
                throw new ApiFailedException();
            }

            Utils.Debug("Starting SamGetMembersInAlias");
            //Get the members in the alias. This returns a list of SIDs
            status = SamGetMembersInAlias(aliasHandle, out var members, out var count);
            Utils.Debug($"SamGetMembersInAlias returned {status}");
            if (!status.Equals(NtStatus.StatusSuccess))
            {
                SamCloseHandle(aliasHandle);
                SamCloseHandle(domainHandle);
                SamCloseHandle(serverHandle);
                throw new ApiFailedException();
            }

            Utils.Debug("Cleaning up handles");
            SamCloseHandle(aliasHandle);
            SamCloseHandle(domainHandle);
            SamCloseHandle(serverHandle);

            if (count == 0)
            {
                SamFreeMemory(members);
                return new SamEnumerationObject[0];
            }

            Utils.Debug("Copying data");
            //Copy the data of our sids to a new array so it doesn't get eaten
            var grabbedSids = new IntPtr[count];
            Marshal.Copy(members, grabbedSids, 0, count);

            var sids = new string[count];

            //Convert the bytes to strings for usage
            for (var i = 0; i < count; i++)
            {
                try
                {
                    sids[i] = new SecurityIdentifier(grabbedSids[i]).Value;
                }
                catch
                {
                    sids[i] = null;
                }
            }

            

            Utils.Debug("Starting LsaOpenPolicy");
            //Open the LSA policy on the target machine
            var obja = default(OBJECT_ATTRIBUTES);
            status = LsaOpenPolicy(ref server, ref obja,
                LsaOpenMask.ViewLocalInfo | LsaOpenMask.LookupNames, out var policyHandle);
            Utils.Debug($"LSAOpenPolicy returned {status}");
            if (!status.Equals(NtStatus.StatusSuccess))
            {
                LsaClose(policyHandle);
                SamFreeMemory(members);
                throw new ApiFailedException();
            }

            Utils.Debug("Starting LSALookupSids");
            var nameList = IntPtr.Zero;
            var domainList = IntPtr.Zero;

            //Call LsaLookupSids using the sids we got from SamGetMembersInAlias
            status = LsaLookupSids(policyHandle, count, members, ref domainList,
                ref nameList);
            Utils.Debug($"LSALookupSids returned {status}");
            if (!status.Equals(NtStatus.StatusSuccess) && !status.Equals(NtStatus.StatusSomeMapped))
            {
                LsaClose(policyHandle);
                LsaFreeMemory(domainList);
                LsaFreeMemory(nameList);
                SamFreeMemory(members);
                throw new ApiFailedException();
            }

            Utils.Debug("Finished API calls");
            //Convert the returned names into structures
            var iter = nameList;
            var translatedNames = new LsaTranslatedNames[count];
            Utils.Debug("Resolving names");
            for (var i = 0; i < count; i++)
            {
                translatedNames[i] = (LsaTranslatedNames)Marshal.PtrToStructure(iter, typeof(LsaTranslatedNames));
                iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(typeof(LsaTranslatedNames)));
            }

            Utils.Debug("Resolving domains");
            //Convert the returned domain list to a structure
            var lsaDomainList =
                (LsaReferencedDomainList)(Marshal.PtrToStructure(domainList, typeof(LsaReferencedDomainList)));

            //Convert the domain list to individual structures
            var trustInfos = new LsaTrustInformation[lsaDomainList.count];
            iter = lsaDomainList.domains;
            for (var i = 0; i < lsaDomainList.count; i++)
            {
                trustInfos[i] = (LsaTrustInformation)Marshal.PtrToStructure(iter, typeof(LsaTrustInformation));
                iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(typeof(LsaTrustInformation)));
            }

            Utils.Debug("Matching up data");
            var resolvedObjects = new SamEnumerationObject[translatedNames.Length];

            //Match up sids, domain names, and account names
            for (var i = 0; i < translatedNames.Length; i++)
            {
                var x = translatedNames[i];

                if (x.DomainIndex > trustInfos.Length || x.DomainIndex < 0 || trustInfos.Length == 0)
                    continue;

                resolvedObjects[i] =
                    new SamEnumerationObject
                    {
                        AccountDomain = trustInfos[x.DomainIndex].name.ToString(),
                        AccountName = x.Name.ToString(),
                        AccountSid = sids[i],
                        SidUsage = x.Use
                    };
            }

            Utils.Debug("Cleaning up");
            //Cleanup
            SamFreeMemory(members);
            LsaFreeMemory(domainList);
            LsaFreeMemory(nameList);
            LsaClose(policyHandle);
            Utils.Debug("Done NetLocalGroupGetMembers");
            return resolvedObjects;
        }

        public static IEnumerable<LocalMember> GetGroupMembers(ResolvedEntry entry, LocalGroupRids rid)
        {
            if (rid.Equals(LocalGroupRids.Administrators) && !Utils.IsMethodSet(ResolvedCollectionMethod.LocalAdmin))
                yield break;

            if (rid.Equals(LocalGroupRids.RemoteDesktopUsers) && !Utils.IsMethodSet(ResolvedCollectionMethod.RDP))
                yield break;

            if (rid.Equals(LocalGroupRids.DcomUsers) && !Utils.IsMethodSet(ResolvedCollectionMethod.DCOM))
                yield break;

            Utils.Debug("Starting GetSamAdmins");
            string machineSid = null;
            Utils.Debug("Starting Task");
            var t = Task<SamEnumerationObject[]>.Factory.StartNew(() =>
            {
                try
                {
                    return NetLocalGroupGetMembers(entry, (int)rid, out machineSid);
                }
                catch (ApiFailedException)
                {
                    return new SamEnumerationObject[0];
                }
                catch (SystemDownException)
                {
                    return new SamEnumerationObject[0];
                }
            });

            var success = t.Wait(Timeout);

            Utils.Debug("Task Finished");

            if (!success)
            {
                Utils.Debug("SamAdmin Timeout");
                throw new TimeoutException();
            }

            Utils.Debug("SamAdmin success");
            var resolvedObjects = t.Result;

            if (resolvedObjects.Length == 0)
            {
                Utils.Debug("SamAdmins returned 0 objects");
                yield break;
            }

            Utils.Debug("Processing data");
            //Process our list of stuff now
            foreach (var data in resolvedObjects)
            {
                var sid = data?.AccountSid;
                Utils.Debug($"Processing sid: {sid}");
                if (sid == null)
                {
                    Utils.Debug("Null sid");
                    continue;
                }

                if (data.AccountName.Equals(string.Empty))
                {
                    Utils.Debug("Empty AccountName");
                    continue;
                }
                    

                if (sid.StartsWith(machineSid))
                {
                    Utils.Debug("Local Account");
                    continue;
                }
                    

                string type;
                switch (data.SidUsage)
                {
                    case SidNameUse.SidTypeUser:
                        type = "user";
                        break;
                    case SidNameUse.SidTypeGroup:
                        type = "group";
                        break;
                    case SidNameUse.SidTypeComputer:
                        type = "computer";
                        break;
                    case SidNameUse.SidTypeWellKnownGroup:
                        type = "wellknown";
                        break;
                    case SidNameUse.SidTypeAlias:
                        type = "group";
                        break;
                    default:
                        type = null;
                        break;
                }

                if (type == null)
                    continue;

                if (data.AccountName.EndsWith("$"))
                    type = "unknown";

                string resolvedName;

                Utils.Debug($"Object Type: {type}");

                if (type.Equals("unknown"))
                {
                    Utils.Debug("Resolving Sid to object UnknownType");
                    var mp = _utils.UnknownSidTypeToDisplay(sid, _utils.SidToDomainName(sid),
                        AdminProps);
                    if (mp == null)
                        continue;

                    Utils.Debug($"Got Object: {mp.PrincipalName}");
                    resolvedName = mp.PrincipalName;
                    type = mp.ObjectType;
                }else if (type == "wellknown")
                {
                    if (MappedPrincipal.GetCommon(sid, out var result))
                    {
                        if (result.PrincipalName.Equals("Local System"))
                        {
                            continue;
                        }

                        string domain;
                        try
                        {
                            var split = string.Join(".", entry.BloodHoundDisplay.Split('.').Skip(1).ToArray());
                            domain = split;
                        }
                        catch
                        {
                            domain = _utils.GetDomain(_options.Domain).Name;
                        }

                        type = result.ObjectType;
                        resolvedName = $"{result.PrincipalName}@{domain}".ToUpper();
                    }
                    else
                    {
                        continue;
                    }

                }
                else
                {
                    Utils.Debug("Resolving Sid to Object");
                    resolvedName = _utils.SidToDisplay(sid, _utils.SidToDomainName(sid), AdminProps, type);
                    if (resolvedName == null)
                        continue;
                    Utils.Debug($"Got Object: {resolvedName}");
                }

                yield return new LocalMember
                {
                    Type = type,
                    Name = resolvedName
                };
            }

            Utils.DoJitter();
        }

        #region hidden

        //public static List<LocalAdmin> LocalGroupWinNt(string target, string group)
        //{
        //    var members = new DirectoryEntry($"WinNT://{target}/{group},group");
        //    var localAdmins = new List<LocalAdmin>();
        //    try
        //    {
        //        foreach (var member in (System.Collections.IEnumerable)members.Invoke("Members"))
        //        {
        //            using (var m = new DirectoryEntry(member))
        //            {
        //                //Convert sid bytes to a string
        //                var sidstring = new SecurityIdentifier(m.GetSid(), 0).ToString();
        //                string type;
        //                switch (m.SchemaClassName)
        //                {
        //                    case "Group":
        //                        type = "group";
        //                        break;
        //                    case "User":
        //                        //If its a user but the name ends in $, it's actually a computer (probably)
        //                        type = m.Properties["Name"][0].ToString().EndsWith("$", StringComparison.Ordinal) ? "computer" : "user";
        //                        break;
        //                    default:
        //                        type = "group";
        //                        break;
        //                }

        //                //Start by checking the cache
        //                if (!_cache.GetMapValue(sidstring, type, out var adminName))
        //                {
        //                    //Get the domain from the SID
        //                    var domainName = _utils.SidToDomainName(sidstring);

        //                    //Search for the object in AD
        //                    var entry = _utils
        //                        .DoSearch($"(objectsid={sidstring})", SearchScope.Subtree, AdminProps, domainName)
        //                        .DefaultIfEmpty(null).FirstOrDefault();

        //                    //If it's not null, we have an object, yay! Otherwise, meh
        //                    if (entry != null)
        //                    {
        //                        adminName = entry.ResolveAdEntry().BloodHoundDisplay;
        //                        _cache.AddMapValue(sidstring, type, adminName);
        //                    }
        //                    else
        //                    {
        //                        adminName = null;
        //                    }
        //                }

        //                if (adminName != null)
        //                {
        //                    localAdmins.Add(new LocalAdmin { ObjectName = adminName, ObjectType = type, Server = target });
        //                }
        //            }
        //        }
        //    }
        //    catch (COMException)
        //    {
        //        //You can get a COMException, so just return a blank array
        //        return localAdmins;
        //    }

        //    return localAdmins;
        //}

        //public static List<LocalAdmin> LocalGroupApi(string target, string group, string domainName, string domainSid)
        //{
        //    const int queryLevel = 2;
        //    var resumeHandle = IntPtr.Zero;
        //    var machineSid = "DUMMYSTRING";

        //    var LMI2 = typeof(LOCALGROUP_MEMBERS_INFO_2);

        //    var returnValue = NetLocalGroupGetMembers(target, group, queryLevel, out IntPtr ptrInfo, -1, out int entriesRead, out int _, resumeHandle);

        //    //Return value of 1722 indicates the system is down, so no reason to fallback to WinNT
        //    if (returnValue == 1722)
        //    {
        //        throw new SystemDownException();
        //    }

        //    //If its not 0, something went wrong, but we can fallback to WinNT provider. Throw an exception
        //    if (returnValue != 0)
        //    {
        //        throw new ApiFailedException();
        //    }

        //    var toReturn = new List<LocalAdmin>();

        //    if (entriesRead <= 0) return toReturn;

        //    var iter = ptrInfo;
        //    var list = new List<API_Encapsulator>();

        //    //Loop through the data and save them into a list for processing
        //    for (var i = 0; i < entriesRead; i++)
        //    {
        //        var data = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(iter, LMI2);
        //        ConvertSidToStringSid(data.lgrmi2_sid, out string sid);
        //        list.Add(new API_Encapsulator
        //        {
        //            Lgmi2 = data,
        //            sid = sid
        //        });
        //        iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(LMI2));
        //    }

        //    NetApiBufferFree(ptrInfo);
        //    //Try and determine the machine sid

        //    foreach (var data in list)
        //    {
        //        if (data.sid == null)
        //        {
        //            continue;
        //        }

        //        //If the sid ends with -500 and doesn't start with the DomainSID, there's a very good chance we've identified the RID500 account
        //        //Take the machine sid from there. If we don't find it, we use a dummy string
        //        if (!data.sid.EndsWith("-500", StringComparison.Ordinal) ||
        //            data.sid.StartsWith(domainSid, StringComparison.Ordinal)) continue;
        //        machineSid = new SecurityIdentifier(data.sid).AccountDomainSid.Value;
        //        break;
        //    }

        //    foreach (var data in list)
        //    {
        //        if (data.sid == null)
        //            continue;
        //        var objectName = data.Lgmi2.lgrmi2_domainandname;
        //        if (objectName.Split('\\').Last().Equals(""))
        //        {
        //            //Sometimes we get weird objects that are just a domain name with no user behind it.
        //            continue;
        //        }

        //        if (data.sid.StartsWith(machineSid, StringComparison.Ordinal))
        //        {
        //            //This should filter out local accounts
        //            continue;
        //        }

        //        string type;
        //        switch (data.Lgmi2.lgrmi2_sidusage)
        //        {
        //            case SID_NAME_USE.SidTypeUser:
        //                type = "user";
        //                break;
        //            case SID_NAME_USE.SidTypeGroup:
        //                type = "group";
        //                break;
        //            case SID_NAME_USE.SidTypeComputer:
        //                type = "computer";
        //                break;
        //            case SID_NAME_USE.SidTypeWellKnownGroup:
        //                type = "wellknown";
        //                break;
        //            default:
        //                type = null;
        //                break;
        //        }

        //        //I have no idea what would cause this condition
        //        if (type == null)
        //        {
        //            continue;
        //        }

        //        if (objectName.EndsWith("$", StringComparison.Ordinal))
        //        {
        //            type = "computer";
        //        }

        //        var resolved = _utils.SidToDisplay(data.sid, _utils.SidToDomainName(data.sid), AdminProps, type);
        //        if (resolved == null)
        //        {
        //            continue;
        //        }

        //        toReturn.Add(new LocalAdmin
        //        {
        //            ObjectName = resolved,
        //            ObjectType = type,
        //            Server = target
        //        });
        //    }
        //    return toReturn;
        //}
        #endregion

        private class TempGPOStorage
        {
            internal int RID { get; set; }
            internal string Name { get; set; }
            internal string Type { get; set; }
        }

        public static IEnumerable<GpoMember> GetGpoMembers(SearchResultEntry entry, string domainName)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.GPOLocalGroup))
                yield break;

            var displayName = entry.GetProp("displayname");
            var name = entry.GetProp("name");
            var path = entry.GetProp("gpcfilesyspath");

            if (displayName == null || name == null || path == null)
            {
                yield break;
            }

            var resolvedList = new List<TempGPOStorage>();

            var template = $"{path}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf";
            
            if (File.Exists(template))
            {
                var content = File.ReadAllText(template);
                var mMatch = MemberRegex.Match(content);

                if (mMatch.Success)
                {
                    var memberText = mMatch.Groups[1].Value;
                    var lines = Regex.Split(memberText.Trim(), @"\r\n|\r|\n");
                    foreach (var line in lines)
                    {
                        var kMatch = KeyRegex.Match(line);

                        var key = kMatch.Groups[1].Value.Trim();
                        var val = kMatch.Groups[2].Value.Trim();

                        var keyMatch = MemberLeftRegex.Match(key);
                        var valMatch = MemberRightRegex.Matches(val);

                        //The first case is when the members of a local group are explicitly set
                        if (keyMatch.Success)
                        {
                            var rid = int.Parse(ExtractRid.Match(keyMatch.Value).Groups[1].Value);
                            foreach (var member in val.Split(','))
                            { 
                                var sid = GetSid(member.Trim('*'), domainName);
                                if (sid == null)
                                    continue;
                                var obj = _utils.UnknownSidTypeToDisplay(sid, _utils.SidToDomainName(sid), Props);
                                if (obj == null)
                                    continue;
                                resolvedList.Add(new TempGPOStorage
                                {
                                    Name = obj.PrincipalName,
                                    RID = rid,
                                    Type = obj.ObjectType
                                });
                            }
                        }

                        //A group has been set as memberof to one of our rids
                        var index = key.IndexOf("MemberOf", StringComparison.CurrentCultureIgnoreCase);
                        if (valMatch.Count > 0 && index > 0)
                        {
                            var sid = key.Trim('*').Substring(0, index - 3);
                            var obj = _utils.UnknownSidTypeToDisplay(sid, _utils.SidToDomainName(sid), Props);
                            if (obj != null)
                            {
                                foreach (var x in valMatch)
                                {
                                    var rid = int.Parse(ExtractRid.Match(x.ToString()).Groups[1].Value);
                                    resolvedList.Add(new TempGPOStorage
                                    {
                                        Name = obj.PrincipalName,
                                        RID = rid,
                                        Type = obj.ObjectType
                                    });
                                }
                            }
                        }
                    }
                }
            }

            var xml = $"{path}\\MACHINE\\Preferences\\Groups\\Groups.xml";

            if (File.Exists(xml))
            {
                var doc = new XPathDocument(xml);
                var nav = doc.CreateNavigator();
                var nodes = nav.Select("/Groups/Group");

                while (nodes.MoveNext())
                {
                    var properties = nodes.Current.Select("Properties");
                    while (properties.MoveNext())
                    {
                        var groupSid = properties.Current.GetAttribute("groupSid", "");
                        if (groupSid == "")
                            continue;

                        if (!groupSid.Equals("S-1-5-32-544"))
                            continue;

                        var rid = int.Parse(ExtractRid.Match(groupSid).Groups[1].Value);

                        var members = properties.Current.Select("Members");
                        while (members.MoveNext())
                        {
                            var subMembers = members.Current.Select("Member");
                            while (subMembers.MoveNext())
                            {
                                var action = subMembers.Current.GetAttribute("action", "");
                                if (action.Equals("ADD"))
                                {
                                    var sid = subMembers.Current.GetAttribute("sid", "");
                                    if (string.IsNullOrEmpty(sid))
                                        continue;
                                    var resolvedPrincipal = _utils.UnknownSidTypeToDisplay(sid, domainName, Props);
                                    if (resolvedPrincipal != null)
                                        resolvedList.Add(new TempGPOStorage
                                        {
                                            RID = rid,
                                            Name = resolvedPrincipal.PrincipalName,
                                            Type = resolvedPrincipal.ObjectType
                                        });
                                }
                            }
                        }
                    }
                }
            }

            var affected = new List<string>();
            if (resolvedList.Count > 0)
            {
                
                foreach (var ouObject in _utils.DoSearch($"(gplink=*{name}*)", SearchScope.Subtree, GpLinkProps, domainName))
                {
                    var adspath = ouObject.DistinguishedName;

                    foreach (var compEntry in _utils.DoSearch("(objectclass=computer)", SearchScope.Subtree, GpoProps,
                        domainName, adspath))
                    {
                        var samAccountType = compEntry.GetProp("samaccounttype");
                        if (samAccountType == null || samAccountType != "805306369")
                            continue;

                        var server = compEntry.ResolveAdEntry()?.BloodHoundDisplay;

                        if (server == null)
                            continue;

                        affected.Add(server);
                    }
                }
            }

            if (affected.Count > 0)
            {
                var g = new GpoMember
                {
                    AffectedComputers = affected.ToArray(),
                    LocalAdmins = resolvedList.Where((x) => x.RID == 544).Select((x) => new LocalMember
                    {
                        Name = x.Name,
                        Type = x.Type
                    }).ToArray(),
                    RemoteDesktopUsers = resolvedList.Where((x) => x.RID == 555).Select((x) => new LocalMember
                    {
                        Name = x.Name,
                        Type = x.Type
                    }).ToArray(),
                    DcomUsers = resolvedList.Where((x) => x.RID == 562).Select((x) => new LocalMember
                    {
                        Name = x.Name,
                        Type = x.Type
                    }).ToArray()
                };

                yield return g;
            }
        }

        private static string GetSid(string element, string domainName)
        {
            string sid;
            if (!element.StartsWith("S-1-", StringComparison.CurrentCulture))
            {
                string domain;
                string target;
                if (element.Contains('\\'))
                {
                    var split = element.Split('\\');
                    var td = _utils.GetDomain(split[0]);
                    if (td == null)
                    {
                        return null;
                    }

                    domain = td.Name;
                    target = split[1];
                }
                else
                {
                    domain = domainName;
                    target = element;
                }

                try
                {
                    sid = _utils.DoSearch($"(samaccountname={target})", SearchScope.Subtree, new []
                    {
                        "objectsid"
                    }, domain).FirstOrDefault().GetSid();
                }
                catch
                {
                    sid = null;
                }
            }
            else
            {
                sid = element;
            }
            return sid;
        }

        private class SamEnumerationObject
        {
            internal string AccountName { get; set; }
            internal string AccountDomain { get; set; }
            internal string AccountSid { get; set; }
            internal SidNameUse SidUsage { get; set; }
        }

        internal enum LocalGroupRids
        {
            Administrators = 544,
            RemoteDesktopUsers = 555,
            DcomUsers = 562
        }

        #region LSA Imports
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus LsaLookupSids(
            IntPtr policyHandle,
            int count,
            IntPtr enumBuffer,
            ref IntPtr domainList,
            ref IntPtr nameList
        );

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaOpenPolicy(
            ref UNICODE_STRING server,
            ref OBJECT_ATTRIBUTES objectAttributes,
            LsaOpenMask desiredAccess,
            out IntPtr policyHandle
        );

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaFreeMemory(
            IntPtr buffer
        );

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaClose(
            IntPtr buffer
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LsaTrustInformation
        {
            internal LsaUnicodeString name;
            private IntPtr sid;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LsaUnicodeString
        {
            private ushort length;
            private ushort maxLen;
            [MarshalAs(UnmanagedType.LPWStr)] private string name;

            public override string ToString()
            {
                return $"{name.Substring(0, length / 2)}";
            }
        }
        #pragma warning disable 649
        private struct LsaTranslatedNames
        {
            internal SidNameUse Use;
            internal LsaUnicodeString Name;
            internal int DomainIndex;
        }
        #pragma warning restore 649

        private struct LsaReferencedDomainList
        {
        #pragma warning disable 649
            internal uint count;

            internal IntPtr domains;
        #pragma warning restore 649
        }

        private enum SidNameUse
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }
        #endregion

        #region SAMR Imports

        [DllImport("samlib.dll")]
        private static extern NtStatus SamCloseHandle(
            IntPtr handle
        );

        [DllImport("samlib.dll")]
        private static extern NtStatus SamFreeMemory(
            IntPtr handle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamLookupDomainInSamServer(
            IntPtr serverHandle,
            ref UNICODE_STRING name,
            out IntPtr sid);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamGetMembersInAlias(
            IntPtr aliasHandle,
            out IntPtr members,
            out int count);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamOpenAlias(
            IntPtr domainHandle,
            AliasOpenFlags desiredAccess,
            int aliasId,
            out IntPtr aliasHandle
        );


        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamConnect(
            ref UNICODE_STRING serverName,
            out IntPtr serverHandle,
            SamAccessMasks desiredAccess,
            ref OBJECT_ATTRIBUTES objectAttributes
            );

        //[DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        //private static extern NTSTATUS SamEnumerateAliasesInDomain(
        //    IntPtr domainHandle,
        //    ref int enumerationContext,
        //    out IntPtr buffer,
        //    int preferredMaxLen,
        //    out int count
        //    );

        //[DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        //private static extern NTSTATUS SamOpenAlias(
        //    IntPtr domainHandle,
        //    SamAliasFlags desiredAccess,
        //    int aliasId,
        //    out IntPtr aliasHandle
        //);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamOpenDomain(
            IntPtr serverHandle,
            DomainAccessMask desiredAccess,
            [MarshalAs(UnmanagedType.LPArray)]byte[] domainSid,
            out IntPtr domainHandle
        );

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        private enum AliasOpenFlags
        {
            AddMember = 0x1,
            RemoveMember = 0x2,
            ListMembers = 0x4,
            ReadInfo = 0x8,
            WriteAccount = 0x10,
            AllAccess = 0xf001f,
            Read = 0x20004,
            Write = 0x20013,
            Execute = 0x20008
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        private enum LsaOpenMask
        {
            ViewLocalInfo = 0x1,
            ViewAuditInfo = 0x2,
            GetPrivateInfo = 0x4,
            TrustAdmin = 0x8,
            CreateAccount = 0x10,
            CreateSecret = 0x20,
            CreatePrivilege = 0x40,
            SetDefaultQuotaLimits = 0x80,
            SetAuditRequirements = 0x100,
            AuditLogAdmin = 0x200,
            ServerAdmin = 0x400,
            LookupNames = 0x800,
            Notification = 0x1000
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        private enum DomainAccessMask
        {
            ReadPasswordParameters = 0x1,
            WritePasswordParameters = 0x2,
            ReadOtherParameters = 0x4,
            WriteOtherParameters = 0x8,
            CreateUser = 0x10,
            CreateGroup = 0x20,
            CreateAlias = 0x40,
            GetAliasMembership = 0x80,
            ListAccounts = 0x100,
            Lookup = 0x200,
            AdministerServer = 0x400,
            AllAccess = 0xf07ff,
            Read = 0x20084,
            Write = 0x2047A,
            Execute = 0x20301
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        private enum SamAliasFlags
        {
            AddMembers = 0x1,
            RemoveMembers = 0x2,
            ListMembers = 0x4,
            ReadInfo = 0x8,
            WriteAccount = 0x10,
            AllAccess = 0xf001f,
            Read = 0x20004,
            Write = 0x20013,
            Execute = 0x20008
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        private enum SamAccessMasks
        {
            SamServerConnect = 0x1,
            SamServerShutdown = 0x2,
            SamServerInitialize = 0x4,
            SamServerCreateDomains = 0x8,
            SamServerEnumerateDomains = 0x10,
            SamServerLookupDomain = 0x20,
            SamServerAllAccess = 0xf003f,
            SamServerRead = 0x20010,
            SamServerWrite = 0x2000e,
            SamServerExecute = 0x20021
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING : IDisposable
        {
            private ushort Length;
            private ushort MaximumLength;
            private IntPtr Buffer;

            public UNICODE_STRING(string s)
                : this()
            {
                if (s == null) return;
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                if (Buffer == IntPtr.Zero) return;
                Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return (Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(Buffer) : null) ?? throw new InvalidOperationException();
            }
        }
        #pragma warning disable 169
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        private struct OBJECT_ATTRIBUTES : IDisposable
        {
            public void Dispose()
            {
                if (objectName == IntPtr.Zero) return;
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }

            public int len;
            public IntPtr rootDirectory;
            public uint attribs;
            public IntPtr sid;
            public IntPtr qos;
            private IntPtr objectName;
            public UNICODE_STRING ObjectName;
        }
        #pragma warning restore 169

        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        private enum NtStatus
        {
            StatusSuccess = 0x0,
            StatusMoreEntries = 0x105,
            StatusSomeMapped = 0x107,
            StatusInvalidHandle = unchecked((int)0xC0000008),
            StatusInvalidParameter = unchecked((int)0xC000000D),
            StatusAccessDenied = unchecked((int)0xC0000022),
            StatusObjectTypeMismatch = unchecked((int)0xC0000024),
            StatusNoSuchDomain = unchecked((int)0xC00000DF),
            StatusRpcServerUnavailable = unchecked((int)0xC0020017)
        }
        #endregion
    }
}
