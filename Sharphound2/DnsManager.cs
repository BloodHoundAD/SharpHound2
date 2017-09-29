using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace Sharphound2
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    internal static class DnsManager
    {
        private static readonly ConcurrentDictionary<string, string> _dnsCache = new ConcurrentDictionary<string, string>();

        /// <summary>
        /// Resolves a host using DNS and suppresses LLMNR and NBNS
        /// </summary>
        /// <param name="host">The host to resolve</param>
        /// <param name="name">The full hostname of the host returned after resolution</param>
        /// <returns>Boolean representing if the host exists in DNS</returns>
       internal static bool HostExistsDns(string host, out string name)
        {
            if (_dnsCache.TryGetValue(host, out name))
            {
                return name != null;
            }
            //We actually dont care about a couple vars, but we need to pass them in for the API call
            var zero = IntPtr.Zero;
            var zero2 = IntPtr.Zero;
            //2176 will disable NBNT and LLMNR
            var result = DnsQuery(host, DnsType.TypeA, 2176uL, ref zero, out var results, zero2);
            //0 is a successful DNS lookup
            if (result == 0)
            {
                try
                {
                    var record = (TypeADnsRecord) Marshal.PtrToStructure(results, typeof(TypeADnsRecord));
                    //Get the name from the record
                    name = Marshal.PtrToStringUni(record.name);
                    //Free the memory we grabbed
                    DnsRecordListFree(results, DnsFreeType.DnsFreeFlat);
                    _dnsCache.TryAdd(host, name);
                    return true;
                }
                catch
                {
                    // ignored
                }
            }
            result = DnsQuery(host, DnsType.TypeAaaa, 2176uL, ref zero, out results, zero2);
            if (result == 0)
            {
                try
                {
                    var record = (TypeADnsRecord) Marshal.PtrToStructure(results, typeof(TypeADnsRecord));
                    name = Marshal.PtrToStringUni(record.name);
                    DnsRecordListFree(results, DnsFreeType.DnsFreeFlat);
                    _dnsCache.TryAdd(host, name);
                    return true;
                }
                catch
                {
                    //ignored
                }
                
            }
            //Make sure the memory is freed. Neither ipv4 or ipv6 succeeded so return false
            //This host probably doesn't have a matching DNS entry, or at least not one we can find
            DnsRecordListFree(results, DnsFreeType.DnsFreeFlat);
            name = null;
            _dnsCache.TryAdd(host, null);
            return false;
        }


        #region PInvoke
        #pragma warning disable 169
        [DllImport("dnsapi", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode)]
        private static extern int DnsQuery(
            [MarshalAs(UnmanagedType.LPWStr)] string name,
            DnsType type,
            ulong options,
            ref IntPtr extra,
            out IntPtr results,
            IntPtr reserved
        );

        [DllImport("dnsapi")]
        private static extern void DnsRecordListFree(
            IntPtr recordList,
            DnsFreeType freeType
        );
        
        #pragma warning disable 649
        private struct TypeADnsRecord
        {
            public IntPtr next;
            public IntPtr name;
            public ushort type;
            public ushort length;
            public DnsRecordFlag flags;
            public uint ttl;
            public uint reserved;
            public ARecordType aRecord;
        }
        #pragma warning restore 649

        private struct ARecordType
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] record;
        }

        //private struct DnsRecord
        //{
        //    public IntPtr nextRecord;
        //    [MarshalAs(UnmanagedType.LPWStr)] public string name;
        //    public DnsType type;
        //    public ushort dataLength;
        //    public DnsRecordFlag flags;
        //    public uint ttl;
        //    public uint reserved;
        //}

        private struct DnsRecordFlag
        {
            private ulong section;
            private ulong delete;
            private ulong charset;
            private ulong unused;
            private ulong reserved;
        }

        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        private enum DnsFreeType
        {
            DnsFreeFlat = 0,
            DnsFreeRecordList = 1,
            DnsFreeParsedMessagedFields = 2
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        private enum DnsType : ushort
        {
            TypeA = 0x1,
            TypeNs = 0x2,
            TypeCname = 0x5,
            TypeSoa = 0x6,
            TypeNull = 0xa,
            TypePtr = 0xc,
            TypeMx = 0xf,
            TypeText = 0x10,
            TypeAaaa = 0x1c,
            TypeSrc = 0x21,
            TypeAxfr = 0xfc,
            TypeAll = 0xff,
            TypeAny = 0xff,
            TypeWins = 0xff01,
            Nbstat = 0xff02
        }
        #pragma warning restore 169
        #endregion
    }
}
