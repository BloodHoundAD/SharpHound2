using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using Sharphound2.Enumeration;
using Sharphound2.JsonObjects;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            foreach (var s in Utils.Instance.DoSearch("(objectclass=*)", SearchScope.Base, new []{"ntsecuritydescriptor", "name", "samaccounttype"}, adsPath: host))
            {
                Console.WriteLine(s.GetProp("name"));
                var a = new Group();
                
                AclHelpers.GetObjectAces(s, s.ResolveAdEntry(), ref a);
            }
        }
    }
}
