using CommandLine;
using Sharphound2.Enumeration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using CommandLine.Text;
using static Sharphound2.CollectionMethod;

namespace Sharphound2
{
    class Sharphound
    {
        public class Options
        {
            [Option('c', "CollectionMethod", DefaultValue = Default, HelpText = "Collection Method (Group, LocalGroup, GPOLocalGroup, Session, LoggedOn, ComputerOnly, Trusts, Stealth, Default")]
            public CollectionMethod CollectMethod { get; set; }

            [Option(HelpText = "Use stealth enumeration options", DefaultValue = false)]
            public bool Stealth { get; set; }

            [Option('d', HelpText = "Domain to enumerate", DefaultValue = null, MutuallyExclusiveSet = "DomainOption")]
            public string Domain { get; set; }

            [Option('s',HelpText ="Search the entire forest", DefaultValue = false, MutuallyExclusiveSet = "DomainOption")]
            public bool SearchForest { get; set; }

            [Option('t',HelpText ="Number of Threads to use", DefaultValue =20)]
            public int Threads { get; set; }

            [Option('f', HelpText = "Folder to drop CSV files", DefaultValue = ".")]
            public string CSVFolder { get; set; }

            [Option('p', HelpText = "Prefix for CSV file names", DefaultValue = "")]
            public string CSVPrefix { get; set; }

            [Option(HelpText ="Interval to display progress in milliseconds", DefaultValue =30000)]
            public int StatusInterval { get; set; }

            [Option(HelpText ="Skip ping checks for hosts", DefaultValue =false)]
            public bool SkipPing { get; set; }

            [Option(HelpText ="Timeout in milliseconds for ping timeout", DefaultValue =750)]
            public int PingTimeout { get; set; }

            [Option(HelpText= "Skip Global Catalog Deconfliction", DefaultValue = false)]
            public bool SkipGcDeconfliction { get; set; }
            
            [Option(HelpText = "Filename for the data cache", DefaultValue = "BloodHound.bin")]
            public string CacheFile { get; set; }

            [Option(HelpText = "Invalidate and build new cache", DefaultValue = false)]
            public bool Invalidate { get; set; }

            [Option(HelpText = "Save the cache file to disk", DefaultValue = true)]
            public bool NoSaveCache { get; set; }

            [Option("LoopTime", DefaultValue = 5, HelpText = "Time in minutes between each session loop")]
            public int LoopTime { get; set; }

            [Option("MaxLoopTime", DefaultValue = 0, HelpText = "Total time to continue looping in minutes")]
            public int MaxLoopTime { get; set; }

            [Option('v',HelpText = "Enable verbose output",DefaultValue = false)]
            public bool Verbose { get; set; }

            [ParserState]
            public IParserState LastParserState { get; set; }

            [HelpOption]
            public string GetUsage()
            {
                var text = @"SharpHound v1.0.0
Usage: SharpHound.exe <options>

Enumeration Options:
    -c , --CollectionMethod (Default: Default)
        Default - Enumerate Trusts, Sessions, Local Admin, and Group Membership
        Cache - Only build the LDAP Cache
        Group - Enumerate Group Membership
        LocalGroup - Enumerate Local Admin
        Session - Enumerate Sessions
        SessionLoop - Continuously Enumerate Sessions
        LoggedOn - Enumerate Sessions using Elevation
        ComputerOnly - Enumerate Sessions and Local Admin
        Trusts - Enumerate Domain Trusts
        ACL - Enumerate ACLs

    -s , --SearchForest
        Search the entire forest instead of just current domain

    -d , --Domain (Default: "")
        Search a specific domain
    
    --SkipGCDeconfliction
        Skip Global Catalog deconfliction during session enumeration
        This option can result in more inaccuracies!

    --Stealth
        Use stealth collection options
    

Performance Tuning:
    -t , --Threads (Default: 20)
        The number of threads to use for Enumeration
    
    --PingTimeout (Default: 750)
        Timeout to use when pinging computers in milliseconds

    --SkipPing
        Skip pinging computers (will most likely be slower)
        Use this option if ping is disabled on the network

    --LoopTime
        Amount of time to wait in between session enumeration loops
        Use in conjunction with -c SessionLoop

    --MaxLoopTime
        Overall time to spend looping in minutes. Will stop looping after this time passes
        Use in conjunction with -c SessionLoop
        Default will loop infinitely

Output Options
    -f , --CSVFolder (Default: .)
        The folder in which to store CSV files

    -p , --CSVPrefix (Default: """")
        The prefix to add to your CSV files

    --URI (Default: """")
        The URI for the Neo4j REST API
        Setting this option will disable CSV output
        Format is SERVER:PORT

    --UserPass (Default: """")
        username:password for the Neo4j REST API

Cache Options
    --NoSaveCache
        Dont save the cache to disk to speed up future runs

    --CacheFile (Default: BloodHound.bin)
        Filename for the BloodHound database to write to disk

    --Invalidate
        Invalidate the cache and build a new one

General Options
    -i , --Interval (Default: 30000)
        Interval to display progress during enumeration in milliseconds

    -v , --Verbose
        Display Verbose Output


";

                if (LastParserState?.Errors.Any() != true) return text;
                var errors = new HelpText().RenderParsingErrorsText(this, 2);
                text += errors;

                return text;
            }

            public string CurrentUser { get; set; }

        }

        public static void Main(string[] args)
        {
            if (args == null)
                throw new ArgumentNullException(nameof(args));

            var options = new Options();
            
            if (!Parser.Default.ParseArguments(args, options))
            {
                Console.WriteLine(options.GetUsage());
                return;
            }
            options.CurrentUser = WindowsIdentity.GetCurrent().Name.Split('\\')[1];
            Console.WriteLine("Initializing BloodHound");
            Cache.CreateInstance(options);
            Utils.CreateInstance(options);

            SessionHelpers.Init(options);
            LocalAdminHelpers.Init();
            GroupHelpers.Init();
            AclHelpers.Init();

            if (options.Stealth)
            {
                Console.WriteLine("Note: All stealth options are single threaded");
            }
            
            if (options.CollectMethod.Equals(LocalGroup) && options.Stealth)
            {
                Console.WriteLine("Note: You specified Stealth and LocalGroup which is equivalent to GPOLocalGroup");
                options.CollectMethod = GPOLocalGroup;
            }

            var runner = new EnumerationRunner(options);

            if (options.Stealth)
            {
                runner.StartStealthEnumeration();
            }
            else
            {
                runner.StartEnumeration();
            }
            Cache.Instance.SaveCache();
        }

        public static void InvokeBloodHound(string[] args)
        {
            Main(args);
        }
    }
}
