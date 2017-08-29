using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Runtime.InteropServices;
using Sharphound2.OutputObjects;

namespace Sharphound2.Enumeration
{
    internal static class DomainTrustEnumeration
    {
        private static Utils _utils;

        public static void Init()
        {
            _utils = Utils.Instance;
        }

        public static IEnumerable<DomainTrust> DoTrustEnumeration(string domain)
        {
            if (domain == null || domain.Trim() == "")
                yield break;
            
            Utils.Verbose($"Enumerating trusts for {domain}");

            var dc = _utils
                .DoSearch("(userAccountControl:1.2.840.113556.1.4.803:=8192)", SearchScope.Subtree,
                    new[] {"dnshostname"}, domain).DefaultIfEmpty(null).FirstOrDefault();

            if (dc == null)
                yield break;
            

            const uint flags = 63;
            var ddt = typeof(DS_DOMAIN_TRUSTS);
            var result = DsEnumerateDomainTrusts(dc.GetProp("dnshostname"), flags, out var ptr, out var domainCount);

            if (result != 0)
                yield break;
                
            var array = new DS_DOMAIN_TRUSTS[domainCount];

            var iter = ptr;
                
            //Loop over the data and store it in an array
            for (var i = 0; i < domainCount; i++)
            {
                array[i] = (DS_DOMAIN_TRUSTS) Marshal.PtrToStructure(iter, ddt);
                iter = (IntPtr) (iter.ToInt64() + Marshal.SizeOf(ddt));
            }

            NetApiBufferFree(ptr);

            for (var i = 0; i < domainCount; i++)
            {
                var trust = new DomainTrust {SourceDomain = domain};
                var data = array[i];
                var trustType = (TRUST_TYPE) data.Flags;
                var trustAttribs = (TRUST_ATTRIB) data.TrustAttributes;

                if ((trustType & TRUST_TYPE.DS_DOMAIN_TREE_ROOT) == TRUST_TYPE.DS_DOMAIN_TREE_ROOT)
                    continue;

                trust.TargetDomain = data.DnsDomainName;

                var inbound = (trustType & TRUST_TYPE.DS_DOMAIN_DIRECT_INBOUND) == TRUST_TYPE.DS_DOMAIN_DIRECT_INBOUND;
                var outbound = (trustType & TRUST_TYPE.DS_DOMAIN_DIRECT_OUTBOUND) == TRUST_TYPE.DS_DOMAIN_DIRECT_OUTBOUND;

                if (inbound && outbound)
                {
                    trust.TrustDirection = "Bidirectional";
                }else if (inbound)
                {
                    trust.TrustDirection = "Inbound";
                }
                else
                {
                    trust.TrustDirection = "Outbound";
                }

                trust.TrustType = (trustType & TRUST_TYPE.DS_DOMAIN_IN_FOREST) == TRUST_TYPE.DS_DOMAIN_IN_FOREST ? "ParentChild" : "External";

                if ((trustAttribs & TRUST_ATTRIB.NON_TRANSITIVE) == TRUST_ATTRIB.NON_TRANSITIVE)
                {
                    trust.IsTransitive = false;
                }
                    
                yield return trust;
            }
            
        }

        #region PINVOKE
        [Flags]
        enum TRUST_TYPE : uint
        {
            DS_DOMAIN_IN_FOREST = 0x0001,  // Domain is a member of the forest
            DS_DOMAIN_DIRECT_OUTBOUND = 0x0002,  // Domain is directly trusted
            DS_DOMAIN_TREE_ROOT = 0x0004,  // Domain is root of a tree in the forest
            DS_DOMAIN_PRIMARY = 0x0008,  // Domain is the primary domain of queried server
            DS_DOMAIN_NATIVE_MODE = 0x0010,  // Primary domain is running in native mode
            DS_DOMAIN_DIRECT_INBOUND = 0x0020   // Domain is directly trusting
        }

        [Flags]
        enum TRUST_ATTRIB : uint
        {
            NON_TRANSITIVE = 0x0001,
            UPLEVEL_ONLY = 0x0002,
            FILTER_SIDS = 0x0004,
            FOREST_TRANSITIVE = 0x0008,
            CROSS_ORGANIZATION = 0x0010,
            WITHIN_FOREST = 0x0020,
            TREAT_AS_EXTERNAL = 0x0030
        }

        [StructLayout(LayoutKind.Sequential)]
        struct DS_DOMAIN_TRUSTS
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string NetbiosDomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsDomainName;
            public uint Flags;
            public uint ParentIndex;
            public uint TrustType;
            public uint TrustAttributes;
            public IntPtr DomainSid;
            public Guid DomainGuid;
        }

        [DllImport("Netapi32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Auto)]
        static extern uint DsEnumerateDomainTrusts(string ServerName,
            uint Flags,
            out IntPtr Domains,
            out uint DomainCount);

        [DllImport("Netapi32.dll", EntryPoint = "NetApiBufferFree")]
        static extern uint NetApiBufferFree(IntPtr buffer);

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

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);
        #endregion
    }
}
