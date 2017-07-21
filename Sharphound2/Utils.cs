using ProtoBuf;
using Sharphound2.OutputObjects;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Sharphound2
{
    class Utils
    {
        static Utils HelperInstance;
        readonly ConcurrentDictionary<string, Domain> DomainCache = new ConcurrentDictionary<string, Domain>();
        ConcurrentDictionary<string, string> UserCache;
        ConcurrentDictionary<string, string> GroupCache;
        ConcurrentDictionary<string, string> ComputerCache;
        ConcurrentDictionary<string, string> DomainToSidCache;
        readonly ConcurrentDictionary<string, bool> PingCache = new ConcurrentDictionary<string, bool>();
        readonly ConcurrentDictionary<string, string> DNSToNetbios = new ConcurrentDictionary<string, string>();

        Sharphound.Options options;
        List<string> DomainList;

        public static void CreateInstance(Sharphound.Options cli)
        {
            HelperInstance = new Utils(cli);
        }

        public static Utils Instance
        {
            get
            {
                return HelperInstance;
            }
        }

        public Utils(Sharphound.Options cli)
        {
            options = cli;
            DomainList = CreateDomainList();
            LoadCache();
        }

        public static string ConvertDNToDomain(string dn)
        {
            return dn.Substring(dn.IndexOf("DC=", StringComparison.CurrentCulture)).Replace("DC=", "").Replace(",", ".");
        }

        public bool PingHost(string HostName)
        {
            if (options.SkipPing)
            {
                return true;
            }

            if (options.CollectMethod.Equals(CollectionMethod.SessionLoop))
            {
                return DoPing(HostName);
            }

            if (PingCache.TryGetValue(HostName, out bool HostIsUp))
            {
                return HostIsUp;
            }

            HostIsUp = DoPing(HostName);
            PingCache.TryAdd(HostName, HostIsUp);
            return HostIsUp;
        }

        bool DoPing(string HostName)
        {
            Ping ping = new Ping();
            try
            {
                PingReply reply = ping.Send(HostName, options.PingTimeout);

                if (reply.Status.Equals(IPStatus.Success))
                {
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        void LoadCache(string Filename=null)
        {
            if (Filename == null)
            {
                Filename = "BloodHound.bin";
            }

            if (File.Exists(Filename))
            {
                Console.WriteLine("Loading Cache");
                using (var w = File.OpenRead(Filename))
                {
                    UserCache = Serializer.DeserializeWithLengthPrefix<ConcurrentDictionary<string, string>>(w, PrefixStyle.Base128);
                    GroupCache = Serializer.DeserializeWithLengthPrefix<ConcurrentDictionary<string, string>>(w, PrefixStyle.Base128);
                    ComputerCache = Serializer.DeserializeWithLengthPrefix<ConcurrentDictionary<string, string>>(w, PrefixStyle.Base128);
                    DomainToSidCache = Serializer.DeserializeWithLengthPrefix<ConcurrentDictionary<string, string>>(w, PrefixStyle.Base128);
                }
            }
            else
            {
                UserCache = new ConcurrentDictionary<string, string>();
                GroupCache = new ConcurrentDictionary<string, string>();
                ComputerCache = new ConcurrentDictionary<string, string>();
                DomainToSidCache = new ConcurrentDictionary<string, string>();
            }

            
        }

        public void WriteCache(string Filename = null)
        {
            if (Filename == null)
            {
                Filename = "BloodHound.bin";
            }

            using (var w = File.Create(Filename))
            {
                Serializer.SerializeWithLengthPrefix(w, UserCache, PrefixStyle.Base128);
                Serializer.SerializeWithLengthPrefix(w, GroupCache, PrefixStyle.Base128);
                Serializer.SerializeWithLengthPrefix(w, ComputerCache, PrefixStyle.Base128);
                Serializer.SerializeWithLengthPrefix(w, DomainToSidCache, PrefixStyle.Base128);
            }
        }

        public string SidToDomainName(string sid, string DomainController = null)
        {
            if (DomainToSidCache.TryGetValue(sid, out string DomainName))
            {
                return DomainName;
            }

            using (LdapConnection conn = GetGCConnection(DomainController))
            {
                SearchRequest request = new SearchRequest(null, $"(objectsid={sid})", SearchScope.Subtree, new string[] { "distinguishedname" });
                SearchOptionsControl searchOptions = new SearchOptionsControl(System.DirectoryServices.Protocols.SearchOption.DomainScope);
                request.Controls.Add(searchOptions);
                SearchResponse response = (SearchResponse)conn.SendRequest(request);

                if (response.Entries.Count > 0)
                {
                    DomainName = ConvertDNToDomain(response.Entries[0].DistinguishedName);
                    DomainToSidCache.TryAdd(sid, DomainName);
                    DomainToSidCache.TryAdd(DomainName, sid);
                    return DomainName;
                }

                request = new SearchRequest(null, $"(securityidentifier={sid}", SearchScope.Subtree, new string[] { "distinguishedname " });
                searchOptions = new SearchOptionsControl(System.DirectoryServices.Protocols.SearchOption.DomainScope);
                request.Controls.Add(searchOptions);
                response = (SearchResponse)conn.SendRequest(request);

                if (response.Entries.Count > 0)
                {
                    DomainName = ConvertDNToDomain(response.Entries[0].DistinguishedName);
                    DomainToSidCache.TryAdd(sid, DomainName);
                    DomainToSidCache.TryAdd(DomainName, sid);
                    return DomainName;
                }
            }

            return null;
        }

        public string SidToObject(string sid, string DomainName, string[] props, string type)
        {
            bool found = false;
            string resolved;
            switch (type)
            {
                case "user":
                    found = UserCache.TryGetValue(sid, out resolved);
                    break;
                case "group":
                    found = GroupCache.TryGetValue(sid, out resolved);
                    break;
                case "computer":
                    found = ComputerCache.TryGetValue(sid, out resolved);
                    break;
                case "wellknown":
                    resolved = $"{GetWellKnownSid(sid)}@{DomainName}";
                    found |= resolved != null;
                    break;
                default:
                    resolved = null;
                    break;
            }

            if (found)
            {
                return resolved.ToUpper();
            }

            using (LdapConnection conn = GetLdapConnection(DomainName))
            {
                SearchResponse response = (SearchResponse)conn.SendRequest(GetSearchRequest($"(objectsid={sid})", SearchScope.Subtree, props, DomainName));

                if (response.Entries.Count >= 1)
                {
                    SearchResultEntry e = response.Entries[0];
                    string name = e.ResolveBloodhoundDisplay();
                    if (name != null)
                    {
                        AddMap(sid, type, name);
                    }

                    return name;
                }
            }
            return null;
        }

        public string DNToObject(string dn, string DomainName, string[] props, string type)
        {
            bool found = false;
            string resolved;
            switch (type)
            {
                case "user":
                    found = UserCache.TryGetValue(dn, out resolved);
                    break;
                case "group":
                    found = GroupCache.TryGetValue(dn, out resolved);
                    break;
                case "computer":
                    found = ComputerCache.TryGetValue(dn, out resolved);
                    break;
                default:
                    resolved = null;
                    break;
            }

            if (found)
            {
                return resolved;
            }

            using (LdapConnection conn = GetLdapConnection(DomainName))
            {
                SearchResponse response = (SearchResponse)conn.SendRequest(GetSearchRequest($"(objectclass=*)", SearchScope.Subtree, props, DomainName, dn));

                if (response.Entries.Count >= 1)
                {
                    SearchResultEntry e = response.Entries[0];
                    string name = e.ResolveBloodhoundDisplay();
                    if (name != null)
                    {
                        AddMap(dn, type, name);
                    }

                    return name;
                }
            }
            return null;
        }

        public LdapConnection GetLdapConnection(string DomainName = null, string DomainController = null)
        {
            Domain TargetDomain;
            try
            {
                TargetDomain = GetDomain(DomainName);
            }
            catch
            {
                Console.WriteLine("Unable to contact domain");
                return null;
            }

            DomainName = TargetDomain.Name;
            if (DomainController == null)
            {
                DomainController = TargetDomain.PdcRoleOwner.Name;
            }

            LdapConnection connection = new LdapConnection(new LdapDirectoryIdentifier(DomainController));

            //Add LdapSessionOptions
            LdapSessionOptions lso = connection.SessionOptions;
            lso.ReferralChasing = ReferralChasingOptions.None;
            return connection;
        }

        public LdapConnection GetGCConnection(string DomainController = null)
        {
            if (DomainController == null)
            {
                DomainController = Forest.GetCurrentForest().FindGlobalCatalog().Name;
            }
            LdapConnection connection = new LdapConnection(new LdapDirectoryIdentifier(DomainController, 3268));
            
            return connection;
        }

        public SearchRequest GetSearchRequest(string Filter, SearchScope Scope, string[] Attribs, string DomainName = null, string ADSPath = null)
        {
            Domain TargetDomain;
            try
            {
                TargetDomain = GetDomain(DomainName);
            }
            catch
            {
                Console.WriteLine("Unable to contact domain");
                return null;
            }

            DomainName = TargetDomain.Name;
            if (ADSPath == null)
            {
                ADSPath = $"DC={DomainName.Replace(".", ",DC=")}";
            }
            else
            {
                ADSPath = ADSPath.Replace("LDAP://", "");
            }

            SearchRequest request = new SearchRequest(ADSPath, Filter, Scope, Attribs);

            //Add our search options control
            SearchOptionsControl soc = new SearchOptionsControl(System.DirectoryServices.Protocols.SearchOption.DomainScope);
            request.Controls.Add(soc);

            return request;
        }

        public List<string> GetDomainList()
        {
            return DomainList;
        }

        List<string> CreateDomainList()
        {
            if (options.SearchForest)
            {
                return GetForestDomains();
            }
            if (options.Domain != null)
            {
                return new List<string>() { options.Domain };
            }

            return new List<string>() { GetDomain().Name };
        }

        List<string> GetForestDomains()
        {
            Forest f = Forest.GetCurrentForest();
            List<string> domains = new List<string>();
            foreach (var d in f.Domains)
            {
                domains.Add(d.ToString());
            }

            return domains;
        }

        public Domain GetDomain(string DomainName = null)
        {
            string key = DomainName ?? "UNIQUENULL";

            if (DomainCache.TryGetValue(key, out Domain DomainObj))
            {
                return DomainObj;
            }

            if (DomainName == null)
            {
                DomainObj = Domain.GetCurrentDomain();
            }
            else
            {
                DirectoryContext context = new DirectoryContext(DirectoryContextType.Domain, DomainName);
                DomainObj = Domain.GetDomain(context);
            }

            DomainCache.TryAdd(key, DomainObj);
            return DomainObj;
        }

        public string GetDomainSID(string DomainName = null)
        {
            string key = DomainName ?? "UNIQUENULL";
            if (DomainToSidCache.TryGetValue(DomainName, out string sid))
            {
                return sid;
            }

            Domain d = GetDomain(DomainName);
            sid = new SecurityIdentifier(d.GetDirectoryEntry().Properties["objectsid"].Value as byte[], 0).ToString();

            DomainToSidCache.TryAdd(key, sid);
            DomainToSidCache.TryAdd(sid, d.Name);

            return sid;
        }

        public bool GetMap(string key, string type, out string resolved)
        {
            switch (type)
            {
                case "group":
                    return GroupCache.TryGetValue(key, out resolved);
                case "user":
                    return UserCache.TryGetValue(key, out resolved);
                case "computer":
                    return ComputerCache.TryGetValue(key, out resolved);
                default:
                    resolved = null;
                    return false;
            }
        }

        public void AddMap(string key, string type, string resolved)
        {
            switch (type)
            {
                case "group":
                    GroupCache.TryAdd(key, resolved);
                    return;
                case "user":
                    UserCache.TryAdd(key, resolved);
                    return;
                case "computer":
                    ComputerCache.TryAdd(key, resolved);
                    return;
                default:
                    resolved = null;
                    return;
            }
        }

        public string GetWellKnownSid(string sid)
        {
            string TrimmedSid = sid.Trim('*');
            string result;

            switch (TrimmedSid)
            {
                case "S-1-0":
                    result = "Null Authority";
                    break;
                case "S-1-0-0":
                    result = "Nobody";
                    break;
                case "S-1-1":
                    result = "World Authority";
                    break;
                case "S-1-1-0":
                    result = "Everyone";
                    break;
                case "S-1-2":
                    result = "Local Authority";
                    break;
                case "S-1-2-0":
                    result = "Local";
                    break;
                case "S-1-2-1":
                    result = "Console Logon ";
                    break;
                case "S-1-3":
                    result = "Creator Authority";
                    break;
                case "S-1-3-0":
                    result = "Creator Owner";
                    break;
                case "S-1-3-1":
                    result = "Creator Group";
                    break;
                case "S-1-3-2":
                    result = "Creator Owner Server";
                    break;
                case "S-1-3-3":
                    result = "Creator Group Server";
                    break;
                case "S-1-3-4":
                    result = "Owner Rights";
                    break;
                case "S-1-4":
                    result = "Non-unique Authority";
                    break;
                case "S-1-5":
                    result = "NT Authority";
                    break;
                case "S-1-5-1":
                    result = "Dialup";
                    break;
                case "S-1-5-2":
                    result = "Network";
                    break;
                case "S-1-5-3":
                    result = "Batch";
                    break;
                case "S-1-5-4":
                    result = "Interactive";
                    break;
                case "S-1-5-6":
                    result = "Service";
                    break;
                case "S-1-5-7":
                    result = "Anonymous";
                    break;
                case "S-1-5-8":
                    result = "Proxy";
                    break;
                case "S-1-5-9":
                    result = "Enterprise Domain Controllers";
                    break;
                case "S-1-5-10":
                    result = "Principal Self";
                    break;
                case "S-1-5-11":
                    result = "Authenticated Users";
                    break;
                case "S-1-5-12":
                    result = "Restricted Code";
                    break;
                case "S-1-5-13":
                    result = "Terminal Server Users";
                    break;
                case "S-1-5-14":
                    result = "Remote Interactive Logon";
                    break;
                case "S-1-5-15":
                    result = "This Organization";
                    break;
                case "S-1-5-17":
                    result = "This Organization";
                    break;
                case "S-1-5-18":
                    result = "Local System";
                    break;
                case "S-1-5-19":
                    result = "NT Authority";
                    break;
                case "S-1-5-20":
                    result = "NT Authority";
                    break;
                case "S-1-5-80-0":
                    result = "All Services";
                    break;
                case "S-1-5-32-544":
                    result = "BUILTIN\\Administrators";
                    break;
                case "S-1-5-32-545":
                    result = "BUILTIN\\Users";
                    break;
                case "S-1-5-32-546":
                    result = "BUILTIN\\Guests";
                    break;
                case "S-1-5-32-547":
                    result = "BUILTIN\\Power Users";
                    break;
                case "S-1-5-32-548":
                    result = "BUILTIN\\Account Operators";
                    break;
                case "S-1-5-32-549":
                    result = "BUILTIN\\Server Operators";
                    break;
                case "S-1-5-32-550":
                    result = "BUILTIN\\Print Operators";
                    break;
                case "S-1-5-32-551":
                    result = "BUILTIN\\Backup Operators";
                    break;
                case "S-1-5-32-552":
                    result = "BUILTIN\\Replicators";
                    break;
                case "S-1-5-32-554":
                    result = "BUILTIN\\Pre-Windows 2000 Compatible Access";
                    break;
                case "S-1-5-32-555":
                    result = "BUILTIN\\Remote Desktop Users";
                    break;
                case "S-1-5-32-556":
                    result = "BUILTIN\\Network Configuration Operators";
                    break;
                case "S-1-5-32-557":
                    result = "BUILTIN\\Incoming Forest Trust Builders";
                    break;
                case "S-1-5-32-558":
                    result = "BUILTIN\\Performance Monitor Users";
                    break;
                case "S-1-5-32-559":
                    result = "BUILTIN\\Performance Log Users";
                    break;
                case "S-1-5-32-560":
                    result = "BUILTIN\\Windows Authorization Access Group";
                    break;
                case "S-1-5-32-561":
                    result = "BUILTIN\\Terminal Server License Servers";
                    break;
                case "S-1-5-32-562":
                    result = "BUILTIN\\Distributed COM Users";
                    break;
                case "S-1-5-32-569":
                    result = "BUILTIN\\Cryptographic Operators";
                    break;
                case "S-1-5-32-573":
                    result = "BUILTIN\\Event Log Readers";
                    break;
                case "S-1-5-32-574":
                    result = "BUILTIN\\Certificate Service DCOM Access";
                    break;
                case "S-1-5-32-575":
                    result = "BUILTIN\\RDS Remote Access Servers";
                    break;
                case "S-1-5-32-576":
                    result = "BUILTIN\\RDS Endpoint Servers";
                    break;
                case "S-1-5-32-577":
                    result = "BUILTIN\\RDS Management Servers";
                    break;
                case "S-1-5-32-578":
                    result = "BUILTIN\\Hyper-V Administrators";
                    break;
                case "S-1-5-32-579":
                    result = "BUILTIN\\Access Control Assistance Operators";
                    break;
                case "S-1-5-32-580":
                    result = "BUILTIN\\Access Control Assistance Operators";
                    break;
                default:
                    result = null;
                    break;
            }
            return result;
        }

        #region PINVOKE
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ClientSiteName;
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int DsGetDcName
          (
            [MarshalAs(UnmanagedType.LPTStr)]
            string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)]
            string DomainName,
            [In] int DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)]
            string SiteName,
            [MarshalAs(UnmanagedType.U4)]
            DSGETDCNAME_FLAGS flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
          );

        [DllImport("Netapi32.dll", SetLastError = true)]
        static extern int NetApiBufferFree(IntPtr Buffer);

        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }
        #endregion
    }
}
