﻿using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using ICSharpCode.SharpZipLib.Zip;
using Sharphound2.Enumeration;
using SearchOption = System.DirectoryServices.Protocols.SearchOption;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace Sharphound2
{
    internal class Utils
    {
        private readonly ConcurrentDictionary<string, Domain> _domainCache = new ConcurrentDictionary<string, Domain>();
        private readonly ConcurrentDictionary<string, Forest> _forestCache = new ConcurrentDictionary<string, Forest>();
        private readonly ConcurrentDictionary<string, string> _dnsResolveCache = new ConcurrentDictionary<string, string>();
        private readonly ConcurrentDictionary<string, bool> _pingCache = new ConcurrentDictionary<string, bool>();
        private readonly ConcurrentDictionary<string, string> _netbiosConversionCache = new ConcurrentDictionary<string, string>();

        private readonly TimeSpan _pingTimeout;
        private static Sharphound.Options _options;
        private static readonly Random Rnd = new Random();
        private readonly List<string> _domainList;
        private readonly Cache _cache;
        private static string _fileTimeStamp;

        private readonly ConcurrentDictionary<string, LdapConnection> _ldapConnectionCache;
        private readonly ConcurrentDictionary<string, LdapConnection> _gcConnectionCache;

        private static readonly List<string> UsedFiles = new List<string>();

        public static void CreateInstance(Sharphound.Options cli)
        {
            Instance = new Utils(cli);
            _fileTimeStamp = $"{DateTime.Now:yyyyMMddHHmmss}";
        }

        public static Utils Instance { get; private set; }

        public static void Verbose(string write)
        {
            if (_options.Verbose)
            {
                Console.WriteLine(write);
            }
        }

        public static void Debug(string write)
        {
            if (_options.Debug)
            {
                Console.WriteLine($"Debug: {write}");
            }
        }

        public Utils(Sharphound.Options cli)
        {
            _options = cli;
            _cache = Cache.Instance;
            _domainList = CreateDomainList();
            _pingTimeout = TimeSpan.FromMilliseconds(_options.PingTimeout);
            _ldapConnectionCache = new ConcurrentDictionary<string, LdapConnection>();
            _gcConnectionCache = new ConcurrentDictionary<string, LdapConnection>();
        }

        public static bool IsMethodSet(ResolvedCollectionMethod method)
        {
            if (method.Equals(ResolvedCollectionMethod.SessionLoop) ||
                method.Equals(ResolvedCollectionMethod.LoggedOnLoop))
            {
                return _options.SessionLoopRunning;
            }

            if (_options.SessionLoopRunning)
                return false;
            
            return (_options.ResolvedCollMethods & method) != 0;
        }

        public static string ConvertDnToDomain(string dn)
        {
            return dn.Substring(dn.IndexOf("DC=", StringComparison.CurrentCulture)).Replace("DC=", "").Replace(",", ".");
        }
        
        public string ResolveHost(string hostName)
        {
            if (_dnsResolveCache.TryGetValue(hostName, out var dnsHostName)) return dnsHostName;
            try
            {
                dnsHostName = Dns.GetHostEntry(hostName).HostName;
            }
            catch
            {
                var result = NetWkstaGetInfo(hostName, 100, out var data);
                if (result == 0)
                {
                    var marshalled = (WkstaInfo100) Marshal.PtrToStructure(data, typeof(WkstaInfo100));
                    
                    var dObj = GetDomain(marshalled.lan_group);
                    if (dObj == null)
                    {
                        return null;
                    }

                    var domain = dObj.Name;
                    var nbname = marshalled.computer_name;
                    if (!DnsManager.HostExistsDns($"{nbname}.{domain}", out dnsHostName))
                    {
                        dnsHostName = hostName;
                    }
                }
                else
                {
                    dnsHostName = hostName;
                }
            }

            _dnsResolveCache.TryAdd(hostName, dnsHostName);

            return dnsHostName;
        }

        public static string GetComputerNetbiosName(string server, out string domain)
        {
            var result = NetWkstaGetInfo(server, 100, out var buf);
            domain = null;
            if (result != 0) return null;
            var marshalled = (WorkstationInfo100) Marshal.PtrToStructure(buf, typeof(WorkstationInfo100));
            domain = marshalled.lan_group;
            return marshalled.computer_name;
        }

        public bool PingHost(string hostName)
        {
            if (_options.SkipPing)
            {
                return true;
            }

            if (hostName == null)
            {
                return false;
            }

            var needsPing = IsMethodSet(ResolvedCollectionMethod.LocalGroup) ||
                IsMethodSet(ResolvedCollectionMethod.Session) ||
                IsMethodSet(ResolvedCollectionMethod.LoggedOn) ||
                IsMethodSet(ResolvedCollectionMethod.RDP) ||
                IsMethodSet(ResolvedCollectionMethod.DCOM) ||
                IsMethodSet(ResolvedCollectionMethod.SessionLoop) ||
                IsMethodSet(ResolvedCollectionMethod.LoggedOnLoop) ||
                IsMethodSet(ResolvedCollectionMethod.LocalGroup);
            
            if (!needsPing)
            {
                return true;
            }

            if (_options.SessionLoopRunning)
            {
                return DoPing(hostName);
            }

            if (_pingCache.TryGetValue(hostName, out var hostIsUp))
            {
                return hostIsUp;
            }
            hostIsUp = DoPing(hostName);
            _pingCache.TryAdd(hostName, hostIsUp);
            return hostIsUp;
        }

        internal bool DoPing(string hostname, int port = 445)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect(hostname, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(_pingTimeout);
                    if (!success)
                    {
                        Verbose($"{hostname} did not respond to ping");
                        return false;
                    }

                    client.EndConnect(result);
                }
            }
            catch
            {
                Verbose($"{hostname} did not respond to ping");
                return false;
            }
            return true;
        }

        //private static bool DoPingIcmp(string hostName)
        //{
        //    var ping = new Ping();
        //    try
        //    {
        //        var reply = ping.Send(hostName, _options.PingTimeout);
        //        return reply != null && reply.Status.Equals(IPStatus.Success);
        //    }
        //    catch
        //    {
        //        return false;
        //    }
        //}

        public string SidToDomainName(string sid, string domainController = null)
        {
            Debug($"Creating SecurityIdentifier from {sid}");
            SecurityIdentifier id;
            try
            {
                id = new SecurityIdentifier(sid);
            }
            catch
            {
                return null;
            }
            
            if (id.AccountDomainSid == null)
            {
                Debug($"SecurityIdentifier was null");
                return null;
            }
            var dSid = id.AccountDomainSid.Value;
            Debug($"Got Domain Sid {dSid}");
            if (_cache.GetDomainFromSid(dSid, out var domainName))
            {
                Debug($"Cache hit for SidToDomainName: {domainName}");
                return domainName;
            }

            Debug($"Searching for sid in AD by objectsid");

            var entry = DoSearch($"(objectsid={dSid})", SearchScope.Subtree, new[] {"distinguishedname"}, useGc: true)
                .DefaultIfEmpty(null).FirstOrDefault();

            if (entry != null)
            {
                domainName = ConvertDnToDomain(entry.DistinguishedName);
                Debug($"Converted sid to {domainName}");
                _cache.AddDomainFromSid(dSid, domainName);
                _cache.AddDomainFromSid(domainName, dSid);
                return domainName;
            }

            Debug($"Searching for sid in AD by securityidentifier");
            entry = DoSearch($"(&(objectClass=trustedDomain)(securityidentifier={dSid}))", SearchScope.Subtree, new[] { "cn" }, useGc: true)
                .DefaultIfEmpty(null).FirstOrDefault();

            if (entry != null)
            {
                domainName = entry.GetProp("cn");
                Debug($"Converted sid to {domainName}");
                _cache.AddDomainFromSid(dSid, domainName);
                _cache.AddDomainFromSid(domainName, dSid);
                return domainName;
            }

            Debug($"No sid found");
            return null;
        }

        /// <summary>
        /// Converts a SID to the bloodhound display name.
        /// Checks the cache first, and if that fails tries grabbing the object from AD
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="domainName"></param>
        /// <param name="props"></param>
        /// <param name="type"></param>
        /// <returns>Resolved bloodhound name or null</returns>
        public string SidToDisplay(string sid, string domainName, string[] props, string type)
        {
            var found = false;
            string resolved;

            if (type.Equals("wellknown"))
            {
                resolved = GetWellKnownSid(sid);
                if (resolved != null)
                {
                    found = true;
                    resolved = $"{resolved}@{domainName}";
                }
            }
            else
            {
                found = _cache.GetMapValue(sid, type, out resolved);
            }

            Debug($"Cache Hit for SidToDisplay: {found}");

            if (found)
            {
                return resolved.ToUpper();
            }

            Debug($"Searching domain {domainName} for {sid}");

            var entry = DoSearch($"(objectsid={sid})", SearchScope.Subtree, props, domainName).DefaultIfEmpty(null)
                .FirstOrDefault();

            if (entry == null)
            {
                Debug($"No entry found");
                return null;
            }

            Debug($"Resolving entry to name");
            var name = entry.ResolveAdEntry();
            if (name != null)
            {
                _cache.AddMapValue(sid, type, name.BloodHoundDisplay);
            }
            Debug($"Resolved to {name}");
            return name?.BloodHoundDisplay;
        }

        public MappedPrincipal UnknownSidTypeToDisplay(string sid, string domainName, string[] props)
        {
            if (_cache.GetMapValueUnknownType(sid, out var principal))
            {
                return principal;
            }

            var entry = DoSearch($"(objectsid={sid})", SearchScope.Subtree, props, domainName).DefaultIfEmpty(null)
                .FirstOrDefault();

            var resolvedEntry = entry?.ResolveAdEntry();

            if (resolvedEntry == null)
                return null;

            var name = resolvedEntry.BloodHoundDisplay;
            var type = resolvedEntry.ObjectType;
            if (name != null)
            {
                _cache.AddMapValue(sid, type, name);
            }
            return new MappedPrincipal(name, type);
        }

        public IEnumerable<Wrapper<SearchResultEntry>> DoWrappedSearch(string filter, SearchScope scope, string[] props,
            string domainName = null, string adsPath = null, bool useGc = false)
        {
            var conn = useGc ? GetGcConnection(domainName) : GetLdapConnection(domainName);
            
            if (conn == null)
            {
                Verbose("Unable to contact LDAP");
                yield break;
            }
            var request = GetSearchRequest(filter, scope, props, domainName, adsPath);

            if (request == null)
            {
                Verbose($"Unable to contact domain {domainName}");
                yield break;
            }

            var prc = new PageResultRequestControl(500);
            request.Controls.Add(prc);

            if (IsMethodSet(ResolvedCollectionMethod.ACL))
            {
                var sdfc =
                    new SecurityDescriptorFlagControl { SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner };
                request.Controls.Add(sdfc);
            }

            PageResultResponseControl pageResponse = null;
            while (true)
            {
                SearchResponse response;
                try
                {
                    response = (SearchResponse) conn.SendRequest(request);
                    if (response != null)
                    {
                        pageResponse = (PageResultResponseControl) response.Controls[0];
                    }
                }
                catch (Exception e)
                {
                    Debug("Exception in Domain Searcher.");
                    Debug(e.Message);
                    yield break;
                }
                if (response == null || pageResponse == null) continue;
                foreach (SearchResultEntry entry in response.Entries)
                {
                    yield return new Wrapper<SearchResultEntry>{Item = entry};
                }

                if (pageResponse.Cookie.Length == 0)
                {
                    break;
                }

                prc.Cookie = pageResponse.Cookie;
            }
        }

        public IEnumerable<SearchResultEntry> DoSearch(string filter, SearchScope scope, string[] props,
            string domainName = null, string adsPath = null, bool useGc = false)
        {
            Debug("Creating connection");
            var conn = useGc ? GetGcConnection(domainName) : GetLdapConnection(domainName);
            
            if (conn == null)
            {
                Debug("Connection null");
                yield break;
            }
            Debug("Getting search request");
            var request = GetSearchRequest(filter, scope, props, domainName, adsPath);

            if (request == null)
            {
                Debug($"Unable to contact domain {domainName}");
                Verbose($"Unable to contact domain {domainName}");
                yield break;
            }

            Debug("Creating page control");
            var prc = new PageResultRequestControl(500);
            request.Controls.Add(prc);

            if (IsMethodSet(ResolvedCollectionMethod.ACL))
            {
                var sdfc =
                    new SecurityDescriptorFlagControl { SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner };
                request.Controls.Add(sdfc);
            }

            PageResultResponseControl pageResponse = null;
            Debug("Starting loop");
            while (true)
            {
                SearchResponse response;
                try
                {
                    response = (SearchResponse)conn.SendRequest(request);
                    if (response != null)
                    {
                        pageResponse = (PageResultResponseControl)response.Controls[0];
                    }
                }
                catch (Exception e)
                {
                    Debug("Error in loop");
                    Debug(e.Message);
                    yield break;
                }
                if (response == null || pageResponse == null) continue;
                foreach (SearchResultEntry entry in response.Entries)
                {
                    yield return entry;
                }

                if (pageResponse.Cookie.Length == 0 || response.Entries.Count == 0)
                {
                    Debug("Loop finished");
                    yield break;
                }

                prc.Cookie = pageResponse.Cookie;
            }
        }


        public LdapConnection GetLdapConnection(string domainName = null)
        {
            Domain targetDomain;
            try
            {
                targetDomain = GetDomain(domainName);
            }
            catch
            {
                Verbose($"Unable to contact domain {domainName}");
                return null;
            }

            if (targetDomain == null)
            {
                Verbose($"Unable to contact domain {domainName}");
                return null;
            }

            var port = _options.LdapPort == 0 ? (_options.SecureLdap ? 636 : 389) : _options.LdapPort;
            var domainController = _options.DomainController ?? targetDomain.PdcRoleOwner.Name;

            // check if PDC is reachable, if not iterate though all DC to find a reachable one
            if (!DoPing(domainController, port) && (_options.DomainController is null))
            {
                foreach(DomainController dc in targetDomain.DomainControllers)
                {
                    if (DoPing(dc.Name, port))
                    {
                        domainController = dc.Name;
                        break;
                    }
                }
                return null;
            }

            if (_ldapConnectionCache.TryGetValue(domainController, out var conn))
            {
                return conn;
            }

            

            var identifier =
                new LdapDirectoryIdentifier(domainController, port, false, false);

            var connection = new LdapConnection(identifier) {Timeout = new TimeSpan(0,0,5,0)};

            if (_options.LdapPass != null && _options.LdapUser != null)
            {
                Verbose("Adding Network Credential to connection");
                var cred = new NetworkCredential(_options.LdapUser, _options.LdapPass, targetDomain.Name);
                connection.Credential = cred;
            }

            //Add LdapSessionOptions
            var lso = connection.SessionOptions;
            if (!_options.DisableKerbSigning)
            {
                lso.Signing = true;
                lso.Sealing = true;
            }
            
            if (_options.SecureLdap)
            {
                lso.ProtocolVersion = 3;
                lso.SecureSocketLayer = true;
                if (_options.IgnoreLdapCert)
                    connection.SessionOptions.VerifyServerCertificate = (con, cer) => true;
            }

            lso.ReferralChasing = ReferralChasingOptions.None;
            _ldapConnectionCache.TryAdd(domainController, connection);
            return connection;
        }

        internal void KillConnections()
        {
            foreach (var d in _ldapConnectionCache)
            {
                d.Value.Dispose();
            }
        }

        public LdapConnection GetGcConnection(string domainName = null)
        {
            Domain targetDomain;
            try
            {
                targetDomain = GetDomain(domainName);
            }
            catch
            {
                Verbose($"Unable to contact domain {domainName}");
                return null;
            }

            if (targetDomain == null)
            {
                return null;
            }

            var domainController = _options.DomainController ?? targetDomain.PdcRoleOwner.Name;
            if (_gcConnectionCache.TryGetValue(domainController, out var conn))
            {
                return conn;
            }
            var connection = new LdapConnection(new LdapDirectoryIdentifier(domainController, 3268));

            var lso = connection.SessionOptions;
            if (_options.DisableKerbSigning) return connection;
            lso.Signing = true;
            lso.Sealing = true;

            _gcConnectionCache.TryAdd(domainController, connection);
            return connection;
        }

        public SearchRequest GetSearchRequest(string filter, SearchScope scope, string[] attribs, string domainName = null, string adsPath = null)
        {
            Domain targetDomain;
            try
            {
                targetDomain = GetDomain(domainName);
            }
            catch
            {
                Verbose($"Unable to contact domain {domainName}");
                return null;
            }

            domainName = targetDomain.Name;
            adsPath = adsPath?.Replace("LDAP://", "") ?? $"DC={domainName.Replace(".", ",DC=")}";

            var request = new SearchRequest(adsPath, filter, scope, attribs);
            //Add our search options control
            var soc = new SearchOptionsControl(SearchOption.DomainScope);
            
            request.Controls.Add(soc);

            return request;
        }

        public List<string> GetDomainList()
        {
            return _domainList;
        }

        private List<string> CreateDomainList()
        {
            if (_options.SearchForest)
            {
                return GetForestDomains();
            }
            if (_options.Domain != null)
            {
                return new List<string> { _options.Domain };
            }

            var d = GetDomain();
            if (d != null)
                return new List<string> { GetDomain().Name };
            
            return new List<string>();
        }

        private static List<string> GetForestDomains()
        {
            var f = Forest.GetCurrentForest();
            var domains = new List<string>();
            foreach (Domain d in f.Domains)
            {
                domains.Add(d.Name);
            }

            return domains;
        }

        public Forest GetForest(string domain = null)
        {
            try
            {
                if (domain == null)
                {
                    return Forest.GetCurrentForest();
                }

                var context = new DirectoryContext(DirectoryContextType.Domain, domain);
                var dObj = Domain.GetDomain(context);
                return dObj.Forest;
            }
            catch
            {
                return null;
            }
        }

        public Domain GetDomain(string domainName = null)
        {
            var key = domainName ?? "UNIQUENULL";

            if (_domainCache.TryGetValue(key, out var domainObj))
            {
                return domainObj;
            }
            try
            {
                if (domainName == null)
                {
                    domainObj = Domain.GetCurrentDomain();
                }
                else
                {
                    var context = new DirectoryContext(DirectoryContextType.Domain, domainName);
                    domainObj = Domain.GetDomain(context);
                }
            }
            catch
            {
                domainObj = null;
            }
            

            _domainCache.TryAdd(key, domainObj);
            return domainObj;
        }

        public string GetDomainSid(string domainName = null)
        {
            var key = domainName ?? "UNIQUENULL";
            if (_cache.GetDomainFromSid(domainName, out var sid))
            {
                return sid;
            }
            var entry = DoSearch("(objectclass=*)", SearchScope.Base, new[] {"objectsid"}, domainName)
                .DefaultIfEmpty(null).FirstOrDefault();

            if (entry == null)
                return null;

            sid = entry.GetSid();
            _cache.AddDomainFromSid(key, sid);
            _cache.AddDomainFromSid(sid, domainName);

            return sid;
        }

        public string DomainNetbiosToFqdn(string netbios)
        {
            if (_netbiosConversionCache.TryGetValue(netbios, out string dnsName))
                return dnsName;

            var returnValue = DsGetDcName(null, netbios, 0, null,
                DSGETDCNAME_FLAGS.DS_IS_FLAT_NAME | DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME, out IntPtr pDCI);

            if (returnValue != 0)
                return null;

            var info = (DOMAIN_CONTROLLER_INFO) Marshal.PtrToStructure(pDCI, typeof(DOMAIN_CONTROLLER_INFO));
            NetApiBufferFree(pDCI);

            _netbiosConversionCache.TryAdd(netbios, info.DomainName);
            return info.DomainName;
        }
        

        public static string GetJsonFileName(string baseFileName)
        {
            var usedFName = baseFileName;
            if (_options.RandomFilenames)
            {
                usedFName = $"{Path.GetRandomFileName()}.json";
            }
            else
            {
                usedFName = $"{_fileTimeStamp}_{usedFName}.json";
            }
            var f = _options.JsonPrefix.Equals("") ? usedFName : $"{_options.JsonPrefix}_{usedFName}";

            f = Path.Combine(_options.JsonFolder, f);
            return f;
        }

        public static string GetZipFileName(string baseFile)
        {
            var f = Path.Combine(_options.JsonFolder, baseFile);
            return f;
        }

        public static bool CheckWritePrivs()
        {
            const string filename = "test.json";
            var f = Path.Combine(_options.JsonFolder, filename);
            try
            {
                using (File.Create(f)){}
                File.Delete(f);
                return true;
            }
            catch
            {
                return false;
            }
        }

        internal static void AddUsedFile(string file)
        {
            UsedFiles.Add(file);
        }

        //Sample code from https://stackoverflow.com/questions/54991/generating-random-passwords
        private static string GenerateZipPass()
        {
            const string space = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            var builder = new StringBuilder();
            var random = new Random();
            for (var i = 0; i < 10; i++)
            {
                builder.Append(space[random.Next(space.Length)]);
            }
            return builder.ToString();
        }

        internal static void CompressFiles()
        {
            string usedname;
            if (_options.ZipFileName != null)
            {
                usedname = _options.ZipFileName;
            }
            else
            {
                if (_options.RandomFilenames)
                {
                    usedname = Path.GetRandomFileName() + ".zip";
                }
                else
                {
                    usedname = $"{_fileTimeStamp}_BloodHound.zip";
                }
            }
            var zipfilepath = GetZipFileName(usedname);

            Console.WriteLine($"Compressing data to {zipfilepath}.");
            var password = GenerateZipPass();
            if (_options.EncryptZip)
            {
                Console.WriteLine($"Password for zip file is {password}");
                Console.WriteLine("Unzip the files manually to upload to the interface");
            }
            else
            {
                Console.WriteLine("You can upload this file directly to the UI.");
            }

            var buffer = new byte[4096];
            
            using (var s = new ZipOutputStream(File.Create(zipfilepath)))
            {
                s.SetLevel(9);
                if (_options.EncryptZip)
                {
                    s.Password = password;
                }
                foreach (var file in UsedFiles)
                {
                    var entry = new ZipEntry(Path.GetFileName(file)) {DateTime = DateTime.Now};
                    s.PutNextEntry(entry);

                    using (var fs = File.OpenRead(file))
                    {
                        int source;
                        do
                        {
                            source = fs.Read(buffer, 0, buffer.Length);
                            s.Write(buffer, 0, source);
                        } while (source > 0);
                    }

                    
                    File.Delete(file);
                    
                }

                s.Finish();
                s.Close();
            }

            Console.WriteLine("Finished compressing files!");
        }

        internal static void DoJitter()
        {
            var j = _options.Jitter;
            var t = _options.Throttle;

            if (t == 0)
                return;

            if (j == 0)
            {
                new ManualResetEvent(false).WaitOne(t);
                return;
            }

            var percent = (int)Math.Floor((double)(j * (t / 100)));
            var temp = t + Rnd.Next(-percent, percent);
            new ManualResetEvent(false).WaitOne(temp);
        }

        public string GetWellKnownSid(string sid)
        {
            var trimmedSid = sid.Trim('*');
            string result;

            switch (trimmedSid)
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
        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern int NetWkstaGetInfo([MarshalAs(UnmanagedType.LPWStr)]string servername, uint level, out IntPtr bufPtr);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WorkstationInfo100
        {
            public int platform_id;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string computer_name;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DOMAIN_CONTROLLER_INFO
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
        private static extern int DsGetDcName
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
        private static extern int NetApiBufferFree(IntPtr Buffer);

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

        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern int NetWkstaGetInfo([MarshalAs(UnmanagedType.LPWStr)]string serverName, int level, out IntPtr data);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WkstaInfo100
        {
            public int platform_id;
            public string computer_name;
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }
        #endregion
    }
}
