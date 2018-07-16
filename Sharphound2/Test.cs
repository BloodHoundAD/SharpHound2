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
            var c = new Computer
            {
                Name = "abc"
            };
            var dict = new Dictionary<string, object> {{"os", "test"}, {"log", 123}};
            c.Properties = dict;
            Console.WriteLine(JsonConvert.SerializeObject(c));
        }
    }
}
