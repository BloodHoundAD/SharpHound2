using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Sharphound2.Enumeration;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            //LocalAdminHelpers.LocalGroupApi("primary.testlab.local", "Administrators", "testlab.local", "");
            //LocalAdminHelpers.GetSamAdmins("primary.testlab.local", "S-1-5-21-883232822-274137685-4173207997");
            //Console.WriteLine("Test 1");
            //Console.WriteLine(Dns.GetHostEntry("windows1.testlab.local").Aliases[0]);
            //Console.WriteLine("Test 2");
            //LocalAdminHelpers.GetSamAdmins("primary.testlab.local");
            //Console.WriteLine("Test 3");
            //LocalAdminHelpers.GetSamAdmins("primary.testlab.local", "S-1-5-21-883232822-274137685-4173207997");

            //LocalAdminHelpers.GetSamAdmins("APL-DC27.dom1.jhuapl.edu", "APL-DC27");
            //LocalAdminHelpers.LocalGroupWinNt("primary", "Administrators");
            //var x = LocalAdminHelpers.GetSamAdmins(new ResolvedEntry
            //{
            //    BloodHoundDisplay = "\\\\primary",
            //    ComputerSamAccountName = "primary",
            //    ObjectType = "computer"
            //});

            //foreach (var y in x)
            //{
            //    Console.WriteLine(y.ToCsv());
            //}

            //Console.WriteLine(DnsManager.HostExists("abc123"));
            //Console.WriteLine(DnsManager.HostExistsDns("primary", out var realName));
            //Console.WriteLine(DnsManager.HostExists("primary.testlab.local"));


            Console.WriteLine(Utils.Instance.PingHost(host));
        }
    }
}
