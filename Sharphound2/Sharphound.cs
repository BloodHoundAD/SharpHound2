using CommandLine;
using Sharphound2.Enumeration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2
{
    class Sharphound
    {
        public class Options
        {
            [Option('d', HelpText = "Domain to enumerate", DefaultValue = null)]
            public string Domain { get; set; }

            [Option('s',HelpText ="Search the entire forest", DefaultValue = false)]
            public bool SearchForest { get; set; }

            [Option('t',HelpText ="Number of Threads to use", DefaultValue =20)]
            public int Threads { get; set; }

            [Option('I',HelpText ="Interval to display progress in milliseconds", DefaultValue =30000)]
            public int Interval { get; set; }
        }

        static void Main(string[] args)
        {
            if (args == null)
                throw new ArgumentNullException(nameof(args));

            var options = new Options();

            if (Parser.Default.ParseArguments(args, options))
            {
                Utils.CreateInstance(options);
                GroupMemberEnumeration x = new GroupMemberEnumeration(options);
                x.StartEnumeration();
            }
            
        }
    }
}
