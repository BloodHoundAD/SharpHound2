using System;
using System.Runtime.InteropServices;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            for (int i = 0; i < 20; i++)
            {
                Utils.DoJitter();
            }
        }
    }
}
