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
            var forest = Utils.Instance.GetForest().Schema.Name;
            foreach (var s in Utils.Instance.DoSearch("(schemaIDGUID=*)", SearchScope.Subtree, new []{"schemaidguid", "name"},adsPath:forest))
            {
                Console.WriteLine(s.GetProp("schemaidguid"));
                Console.WriteLine(s.GetProp("name"));
            }
        }
    }
}
