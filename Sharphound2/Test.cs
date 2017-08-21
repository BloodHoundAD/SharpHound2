using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;

namespace Sharphound2
{
    class Test
    {
        public static void DoStuff()
        {
            var x = Utils.Instance.DoSearch("(objectclass=group)", SearchScope.Base, null, "testlab.local", "CN=Domain Admins,CN=Users,DC=testlab,DC=local").DefaultIfEmpty(null).FirstOrDefault();
            Console.WriteLine(x.DistinguishedName);
        }
    }
}
