using System;
using System.Runtime.InteropServices;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            DnsManager.HostExistsDns(host, out var name);
            Console.WriteLine(name);
        }
        
    }
}
