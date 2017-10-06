using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Sharphound2.Enumeration;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            Console.WriteLine(host);
            var result = NetWkstaGetInfo(host, 100, out var data);
            Console.WriteLine(result);
            var info = (WkstaInfo100) Marshal.PtrToStructure(data, typeof(WkstaInfo100));
            Console.WriteLine(info.computer_name);
            Console.WriteLine(info.lan_group);
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
    }
}
