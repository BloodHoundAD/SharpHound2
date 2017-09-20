using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Runtime.InteropServices;
using Sharphound2.Enumeration;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            foreach (var x in Utils.Instance.DoSearch("(objectclass=container)", SearchScope.Subtree,
                new[] {"name", "objectsid", "samaccounttype"}, "testlab.local",
                "CN=User,CN={1CEEC639-B9CE-4668-85F9-AB0A07872C88},CN=Policies,CN=System,DC=testlab, DC = local"))
            {
                Console.WriteLine(x.DistinguishedName);
            }
            //ContainerHelpers.GetContainersForDomain("testlab.local");
        }
    }
}
