using CommandLine;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
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

        public SearchResponse GetSimpleSearcher(string Filter, string[] Attribs, string DomainName = null, string ADSPath = null, string DomainController = null)
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

            if (ADSPath == null)
            {
                ADSPath = $"DC={DomainName.Replace(".", ",DC=")}";
            }
            else
            {
                ADSPath = ADSPath.Replace("LDAP://", "");
            }

            SearchRequest request = new SearchRequest(ADSPath, Filter, SearchScope.Subtree, Attribs);

            //Add our search options control
            SearchOptionsControl soc = new SearchOptionsControl(SearchOption.DomainScope);
            request.Controls.Add(soc);

            //Add LdapSessionOptions
            LdapSessionOptions lso = connection.SessionOptions;
            lso.ReferralChasing = ReferralChasingOptions.All;

            SearchResponse response = (SearchResponse)connection.SendRequest(request);
            return response;
        }

        public SearchResponse GetSingleSearcher(string Filter, string[] Attribs, string DomainName = null, string ADSPath = null, string DomainController = null)
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

            if (ADSPath == null)
            {
                ADSPath = $"DC={DomainName.Replace(".", ",DC=")}";
            }
            else
            {
                ADSPath = ADSPath.Replace("LDAP://", "");
            }

            SearchRequest request = new SearchRequest(ADSPath, Filter, SearchScope.Base, Attribs);

            //Add our search options control
            SearchOptionsControl soc = new SearchOptionsControl(SearchOption.DomainScope);
            request.Controls.Add(soc);

            //Add LdapSessionOptions
            LdapSessionOptions lso = connection.SessionOptions;
            lso.ReferralChasing = ReferralChasingOptions.All;

            SearchResponse response = (SearchResponse)connection.SendRequest(request);
            return response;
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
    }
}
