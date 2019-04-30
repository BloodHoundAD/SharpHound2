using System;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Heijden.DNS;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            var resolver = new Resolver();
            foreach (var x in resolver.DnsServers)
            {
                Console.WriteLine(x.Address);
            }
        }

        
    }
}
