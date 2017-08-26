using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using Sharphound2.Enumeration;

namespace Sharphound2
{
    class Test
    {
        public static void DoStuff()
        {
            //LocalAdminHelpers.LocalGroupApi("primary.testlab.local", "Administrators", "testlab.local", "");
            //LocalAdminHelpers.GetSamAdmins("primary.testlab.local", "S-1-5-21-883232822-274137685-4173207997");
            //Console.WriteLine("Test 1");
            foreach (var x in LocalAdminHelpers.GetSamAdmins("abc123"))
            {
                Console.WriteLine(x.ToCsv());
            }
            //Console.WriteLine("Test 2");
            //LocalAdminHelpers.GetSamAdmins("primary.testlab.local");
            //Console.WriteLine("Test 3");
            //LocalAdminHelpers.GetSamAdmins("primary.testlab.local", "S-1-5-21-883232822-274137685-4173207997");

            //LocalAdminHelpers.GetSamAdmins("APL-DC27.dom1.jhuapl.edu", "APL-DC27");
        }
    }
}
