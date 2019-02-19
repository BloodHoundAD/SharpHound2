using System;
using System.DirectoryServices.Protocols;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            //var forest = "DC=dev,DC=testlab,DC=local";
            foreach (var s in Utils.Instance.DoSearch("(objectsid=S-1-5-9)", SearchScope.Subtree, null,adsPath:host))
            {
                Console.WriteLine(s.GetProp("name"));
                Console.WriteLine(s.DistinguishedName);
            }
        }
    }
}
