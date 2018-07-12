using System;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using Sharphound2.Enumeration;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            var nbt = Utils.GetComputerNetbiosName("192.168.52.20", out var domain);
            Console.WriteLine(nbt);
            Console.WriteLine(domain);
        }
    }
}
