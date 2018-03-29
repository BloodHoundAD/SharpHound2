using System;
using System.Runtime.InteropServices;
using Sharphound2.Enumeration;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            foreach (var d in GroupHelpers.GetEnterpriseDCs(host))
            {
                Console.WriteLine(d.AccountName);
            }
        }
    }
}
