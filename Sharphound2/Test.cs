using System;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            //var forest = "DC=dev,DC=testlab,DC=local";
            var sd = new DirectoryEntry("LDAP://<sid=S-1-5-21-883232822-274137685-4173207997>");
            Console.WriteLine(sd.Properties["distinguishedname"][0].ToString());
        }

        
    }
}
