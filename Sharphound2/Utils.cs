using CommandLine;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace Sharphound2
{
    class Utils
    {
        static Utils HelperInstance;
        readonly ConcurrentDictionary<string, Domain> DomainCache = new ConcurrentDictionary<string, Domain>();
        ConcurrentDictionary<string, string> MapCache = new ConcurrentDictionary<string, string>();
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
        }

        public static string ConvertDNToDomain(string dn)
        {
            return dn.Substring(dn.IndexOf("DC=", StringComparison.CurrentCulture)).Replace("DC=", "").Replace(",", ".");
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
            lso.ReferralChasing = ReferralChasingOptions.All;
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
            SearchOptionsControl soc = new SearchOptionsControl(SearchOption.DomainScope);
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

        public bool GetMap(string key, out string resolved)
        {
            return MapCache.TryGetValue(key, out resolved);
        }

        public void AddMap(string key, string resolved)
        {
            MapCache.TryAdd(key, resolved);
        }

        public string ConvertSIDToName(string sid)
        {
            string TrimmedCN = sid.Trim('*');
            if (MapCache.TryGetValue(TrimmedCN, out string result))
            {
                return result;
            }

            switch (TrimmedCN)
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
                    try
                    {
                        SecurityIdentifier identifier = new SecurityIdentifier(TrimmedCN);
                        result = identifier.Translate(typeof(NTAccount)).Value;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                        result = null;
                    }

                    break;
            }
            MapCache.TryAdd(TrimmedCN, result);
            return result;
        }
    }
}
