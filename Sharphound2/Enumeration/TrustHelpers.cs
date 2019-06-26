using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Runtime.InteropServices;
using Sharphound2.JsonObjects;

namespace Sharphound2.Enumeration
{
    [SuppressMessage("ReSharper", "UnusedMember.Local")]
    internal static class TrustHelpers
    {
        private static Utils _utils;

        public static void Init()
        {
            _utils = Utils.Instance;
        }

        internal static void DoTrustEnumeration(ResolvedEntry resolved, ref Domain obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.Trusts))
                return;

            if (resolved == null)
                return;

            var trusts = new List<Trust>();
            var dc = _utils.GetUsableDomainController(_utils.GetDomain(resolved.BloodHoundDisplay));
            //var dc = _utils
            //    .DoSearch("(userAccountControl:1.2.840.113556.1.4.803:=8192)", SearchScope.Subtree,
            //        new[] { "dnshostname" }, resolved.BloodHoundDisplay).DefaultIfEmpty(null).FirstOrDefault();

            if (dc == null)
                return;


            const uint flags = 63;
            var ddt = typeof(DsDomainTrusts);
            var result = DsEnumerateDomainTrusts(dc, flags, out var ptr, out var domainCount);

            if (result != 0)
                return;

            var array = new DsDomainTrusts[domainCount];

            var iter = ptr;

            //Loop over the data and store it in an array
            for (var i = 0; i < domainCount; i++)
            {
                array[i] = (DsDomainTrusts)Marshal.PtrToStructure(iter, ddt);
                iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(ddt));
            }

            NetApiBufferFree(ptr);

            for (var i = 0; i < domainCount; i++)
            {
                var trust = new Trust();

                var data = array[i];
                var trustFlags = (TrustFlags)data.Flags;
                var trustAttribs = (TrustAttrib)data.TrustAttributes;

                // the domain itself
                if ((trustFlags & TrustFlags.DsDomainPrimary) == TrustFlags.DsDomainPrimary)
                    continue;

                if (data.DnsDomainName == null)
                    continue;
                trust.TargetName = data.DnsDomainName;
                var inbound = (trustFlags & TrustFlags.DsDomainDirectInbound) == TrustFlags.DsDomainDirectInbound;
                var outbound = (trustFlags & TrustFlags.DsDomainDirectOutbound) == TrustFlags.DsDomainDirectOutbound;

                if (inbound && outbound)
                {
                    trust.TrustDirection = (int)TrustDirection.Bidirectional;
                }
                else if (inbound)
                {
                    trust.TrustDirection = (int)TrustDirection.Inbound;
                }
                else if (outbound)
                {
                    trust.TrustDirection = (int)TrustDirection.Outbound;
                }
                else
                {
                    // a trust with no direction is probably not enabled (According to MS documentation)
                    // see: https://docs.microsoft.com/fr-fr/windows/desktop/api/ntsecapi/ns-ntsecapi-_trusted_domain_information_ex (TrustDirection)
                    continue;
                }

                // parentChild occure only when one of the domain is the forest root
                // Check is trusted domain is the current forest root or if trusted domain's parent is current enumerated domain
                if (((trustFlags & TrustFlags.DsDomainTreeRoot) == TrustFlags.DsDomainTreeRoot) && ((trustFlags & TrustFlags.DsDomainInForest) == TrustFlags.DsDomainInForest) || array[data.ParentIndex].DnsDomainName?.ToUpper() == resolved.BloodHoundDisplay)
                {
                    trust.TrustType = "ParentChild";
                }
                else if ((trustFlags & TrustFlags.DsDomainInForest) == TrustFlags.DsDomainInForest)
                {
                    trust.TrustType = "CrossLink";
                }
                else if ((trustAttribs & TrustAttrib.ForestTransitive) == TrustAttrib.ForestTransitive)
                {
                    trust.TrustType = "Forest";
                }
                else
                {
                    trust.TrustType = "External";
                }

                if ((trustAttribs & TrustAttrib.NonTransitive) == TrustAttrib.NonTransitive)
                {
                    trust.IsTransitive = false;
                }
                else
                {
                    trust.IsTransitive = true;
                }

                trusts.Add(trust);
            }

            obj.Trusts = trusts.ToArray();
        }

        #region PINVOKE
        [Flags]
        private enum TrustFlags : uint
        {
            DsDomainInForest = 0x0001,  // Domain is a member of the forest
            DsDomainDirectOutbound = 0x0002,  // Domain is directly trusted
            DsDomainTreeRoot = 0x0004,  // Domain is root of a tree in the forest
            DsDomainPrimary = 0x0008,  // Domain is the primary domain of queried server
            DsDomainNativeMode = 0x0010,  // Primary domain is running in native mode
            DsDomainDirectInbound = 0x0020   // Domain is directly trusting
        }

        [Flags]
        private enum TrustAttrib : uint
        {
            NonTransitive = 0x0001,
            UplevelOnly = 0x0002,
            FilterSids = 0x0004,
            ForestTransitive = 0x0008,
            CrossOrganization = 0x0010,
            WithinForest = 0x0020,
            TreatAsExternal = 0x0040
        }

        [StructLayout(LayoutKind.Sequential)]
        [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Local")]
        private struct DsDomainTrusts
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            private string NetbiosDomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsDomainName;
            public uint Flags;
            public uint ParentIndex;
            private uint TrustTypeA;
            public uint TrustAttributes;
            private IntPtr DomainSid;
            private Guid DomainGuid;
        }

        [DllImport("Netapi32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Auto)]
        private static extern uint DsEnumerateDomainTrusts(string serverName,
            uint flags,
            out IntPtr domains,
            out uint domainCount);

        [DllImport("Netapi32.dll", EntryPoint = "NetApiBufferFree")]
        private static extern uint NetApiBufferFree(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Local")]
        private struct DomainControllerInfo
        {
            [MarshalAs(UnmanagedType.LPTStr)] private string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)] private string DomainControllerAddress;
            private uint DomainControllerAddressType;
            private Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)] private string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)] private string DnsForestName;
            private uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)] private string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)] private string ClientSiteName;
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int DsGetDcName
        (
            [MarshalAs(UnmanagedType.LPTStr)]
            string computerName,
            [MarshalAs(UnmanagedType.LPTStr)]
            string domainName,
            [In] int domainGuid,
            [MarshalAs(UnmanagedType.LPTStr)]
            string siteName,
            [MarshalAs(UnmanagedType.U4)]
            DsGetDcNameFlags flags,
            out IntPtr pDomainControllerInfo
        );

        [Flags]
        public enum DsGetDcNameFlags : uint
        {
            DsForceRediscovery = 0x00000001,
            DsDirectoryServiceRequired = 0x00000010,
            DsDirectoryServicePreferred = 0x00000020,
            DsGcServerRequired = 0x00000040,
            DsPdcRequired = 0x00000080,
            DsBackgroundOnly = 0x00000100,
            DsIpRequired = 0x00000200,
            DsKdcRequired = 0x00000400,
            DsTimeservRequired = 0x00000800,
            DsWritableRequired = 0x00001000,
            DsGoodTimeservPreferred = 0x00002000,
            DsAvoidSelf = 0x00004000,
            DsOnlyLdapNeeded = 0x00008000,
            DsIsFlatName = 0x00010000,
            DsIsDnsName = 0x00020000,
            DsReturnDnsName = 0x40000000,
            DsReturnFlatName = 0x80000000
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);
        #endregion
    }
}
