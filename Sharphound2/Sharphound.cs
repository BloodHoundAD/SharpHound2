using CommandLine;
using Sharphound2.Enumeration;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using CommandLine.Text;
using static Sharphound2.CollectionMethod;

namespace Sharphound2
{
    internal class Sharphound
    {
        public class Options
        {
            [OptionArray('c', "CollectionMethod", DefaultValue = new[] {"Default"}, HelpText = "Collection Method (Group, LocalGroup, GPOLocalGroup, Session, LoggedOn, ComputerOnly, Trusts, Stealth, Default")]
            public string[] CollectionMethod { get; set; }

            [Option(HelpText = "Use stealth enumeration options", DefaultValue = false)]
            public bool Stealth { get; set; }

            [Option('d', HelpText = "Domain to enumerate", DefaultValue = null, MutuallyExclusiveSet = "DomainOption")]
            public string Domain { get; set; }

            [Option('s',HelpText ="Search the entire forest", DefaultValue = false, MutuallyExclusiveSet = "DomainOption")]
            public bool SearchForest { get; set; }

            [Option(DefaultValue = null)]
            public string Ou { get; set; }

            [Option(DefaultValue=null)]
            public string ComputerFile { get; set; }

            [Option('t',"Threads",HelpText ="Number of Threads to use", DefaultValue =10)]
            public int Threads { get; set; }

            [Option(HelpText = "Folder to drop CSV files", DefaultValue = ".")]
            public string CSVFolder { get; set; }

            [Option(HelpText = "Prefix for CSV file names", DefaultValue = "")]
            public string CSVPrefix { get; set; }

            [Option(DefaultValue = null)]
            public string Uri { get; set; }

            [Option(DefaultValue = 0)]
            public int LdapPort { get; set; }

            [Option(DefaultValue = null)]
            public string UserPass { get; set; }

            [Option(HelpText ="Interval to display progress in milliseconds", DefaultValue =30000)]
            public int StatusInterval { get; set; }

            [Option(HelpText ="Skip ping checks for hosts", DefaultValue =false)]
            public bool SkipPing { get; set; }

            [Option(HelpText ="Timeout in milliseconds for ping timeout", DefaultValue =200)]
            public int PingTimeout { get; set; }

            [Option(HelpText= "Skip Global Catalog Deconfliction", DefaultValue = false)]
            public bool SkipGcDeconfliction { get; set; }
            
            [Option(HelpText = "Filename for the data cache", DefaultValue = "BloodHound.bin")]
            public string CacheFile { get; set; }

            [Option(HelpText = "Invalidate and build new cache", DefaultValue = false)]
            public bool Invalidate { get; set; }

            [Option(HelpText = "Don't save the cache file to disk", DefaultValue = false)]
            public bool NoSaveCache { get; set; }

            [Option(DefaultValue = 5, HelpText = "Time in minutes between each session loop")]
            public int LoopTime { get; set; }

            [Option(DefaultValue = null)]
            public string MaxLoopTime { get; set; }

            [Option('v',"Verbose",HelpText = "Enable verbose output",DefaultValue = false)]
            public bool Verbose { get; set; }

            [Option(HelpText = "Exclude Domain Controllers from search (useful for ATA environments)", DefaultValue = false)]
            public bool ExcludeDC { get; set; }

            [Option(DefaultValue = false)]
            public bool SecureLdap { get; set; }

            [Option(DefaultValue = false)]
            public bool IgnoreLdapCert { get; set; }

            [Option(DefaultValue = false)]
            public bool DisableKerbSigning { get; set; }

            [Option(DefaultValue = false)]
            public bool CompressData { get; set; }

            [Option(DefaultValue = null)]
            public string Test { get; set; }

            [Option(DefaultValue = null)]
            public string DomainController { get; set; }
            
            [Option(DefaultValue = false)]
            public bool Debug { get; set; }

            [Option(DefaultValue = false)]
            public bool RemoveCSV { get; set; }

            [Option(DefaultValue = 0)]
            public int Throttle { get; set; }

            [Option(DefaultValue = 0)]
            public int Jitter { get; set; }

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
        Group - Enumerate Group Membership
        LocalGroup - Enumerate Local Admin
        Session - Enumerate Sessions
        SessionLoop - Continuously Enumerate Sessions
        LoggedOn - Enumerate Sessions using Elevation
        ComputerOnly - Enumerate Sessions and Local Admin
        Trusts - Enumerate Domain Trusts
        ACL - Enumerate ACLs
        ObjectProps - Enumerate Object Properties for Users/Computers

        This can be a list of comma seperated valued as well to run multiple collection methods!

    -s , --SearchForest
        Search the entire forest instead of just current domain

    -d , --Domain (Default: "")
        Search a specific domain
    
    --SkipGCDeconfliction
        Skip Global Catalog deconfliction during session enumeration
        This option can result in more inaccuracies!

    --Stealth
        Use stealth collection options

    --Ou (Default: null)
        Ou to limit computer enumeration too. Requires a DistinguishedName (OU=Domain Controllers,DC=contoso,DC=local)

    --ComputerFile (Default: null)
        A file containing a list of computers to enumerate. This option can only be used with the following Collection Methods:
        Session, SessionLoop, LocalGroup, ComputerOnly, LoggedOn

    --DomainController (Default: null)
        Specify which Domain Controller to request data from. Defaults to closest DC using Site Names

    --ExcludeDC
        Exclude domain controllers from session queries. Useful for ATA environments which detect this behavior
   
Connection Options:
    --SecureLdap
        Uses secure LDAP (LDAPS) instead of regular

    --LdapPort
        Override the port used to connect to LDAP

    --IgnoreLdapCert
        Ignores the SSL certificate for LDAP. Use for self-signed certs

    --DisableKerbSigning
        Disables Kerberos signing on LDAP requests

Performance Tuning:
    -t , --Threads (Default: 10)
        The number of threads to use for Enumeration
    
    --PingTimeout (Default: 200)
        Timeout to use when pinging computers in milliseconds

    --SkipPing
        Skip pinging computers (will most likely be slower)
        Use this option if ping is disabled on the network

    --LoopTime
        Amount of time to wait in between session enumeration loops
        Use in conjunction with -c SessionLoop

    --MaxLoopTime
        Time to stop looping. Format is 0d0h0m0s or any variation of this.
        Use in conjunction with -c SessionLoop
        Default will loop infinitely

    --Throttle (Default: 0)
        Time in milliseconds to throttle between requests to computers

    --Jitter (Default: 0)
        Percent jitter to apply to throttle

Output Options
    --CSVFolder (Default: .)
        The folder in which to store CSV files

    --CSVPrefix (Default: """")
        The prefix to add to your CSV files

    --URI (Default: """")
        The URI for the Neo4j REST API
        Setting this option will disable CSV output
        Format is http(s)://SERVER:PORT

    --UserPass (Default: """")
        username:password for the Neo4j REST API

    --CompressData
        Compress CSVs into a zip file after run

    --RemoveCSV
        Removes CSVs after running. Only usable with the CompressData flag

Cache Options
    --NoSaveCache
        Dont save the cache to disk to speed up future runs

    --CacheFile (Default: BloodHound.bin)
        Filename for the BloodHound database to write to disk

    --Invalidate
        Invalidate the cache and build a new one

General Options
    --StatusInterval (Default: 30000)
        Interval to display progress during enumeration in milliseconds

    -v , --Verbose
        Display Verbose Output


";

                if (LastParserState?.Errors.Any() != true) return text;
                var errors = new HelpText().RenderParsingErrorsText(this, 2);
                text += errors;

                return text;
            }

            internal CollectionMethod CurrentCollectionMethod;

            public string CurrentUser { get; set; }

            public DateTime LoopEnd { get; set; }

            public string GetEncodedUserPass()
            {
                var plainTextBytes = Encoding.UTF8.GetBytes(UserPass);
                return Convert.ToBase64String(plainTextBytes);
            }

            public string GetURI()
            {
                return $"{Uri}/db/data/transaction/commit";
            }

            public string GetCheckURI()
            {
                return $"{Uri}/db/data/";
            }
        }

        public static void Main(string[] args)
        {
            if (args == null)
                throw new ArgumentNullException(nameof(args));

            var options = new Options();
            
            if (!Parser.Default.ParseArguments(args, options))
            {
                return;
            }

            try
            {
                // ReSharper disable once ReturnValueOfPureMethodIsNotUsed
                Path.Combine(options.CSVFolder, options.CacheFile);
            }
            catch (ArgumentException)
            {
                Console.WriteLine("Invalid characters in output path. Check for trailing backslashes!");
                return;
            }

            var collectionMethods = new List<CollectionMethod>();
            if (options.CollectionMethod.Length == 1)
            {
                options.CollectionMethod = options.CollectionMethod[0].Split(',');
            }

            if (options.Jitter > 100 || options.Jitter < 0)
            {
                Console.WriteLine("Jitter must be a value between 0 and 100!");
                return;
            }

            if (options.Throttle < 0)
            {
                Console.WriteLine("Throttle must be 0 or greater!");
                return;
            }

            foreach (var unparsed in options.CollectionMethod)
            {
                try
                {
                    var e = (CollectionMethod)Enum.Parse(typeof(CollectionMethod), unparsed, true);
                    collectionMethods.Add(e);
                }
                catch
                {
                    Console.WriteLine($"Failed to parse value {unparsed}. Check your values for CollectionMethods!");
                    return;
                }
            }

            if (options.Debug)
            {
                Console.WriteLine("Debug Mode activated!");
                options.Threads = 1;
            }

            if (options.MaxLoopTime != null && options.CurrentCollectionMethod.Equals(SessionLoop))
            {
                var regex = new Regex("[0-9]+[smdh]");
                var matches = regex.Matches(options.MaxLoopTime);
                var numregex = new Regex("[0-9]+");
                var timeregex = new Regex("[smdh]");
                if (matches.Count == 0)
                {
                    Console.WriteLine("LoopEndTime does not match required format");
                    return;
                }

                var now = DateTime.Now;
                var drift = 0;
                foreach (var match in matches)
                {
                    var num = int.Parse(numregex.Match(match.ToString()).Value);
                    var spec = timeregex.Match(match.ToString());

                    switch (spec.Value)
                    {
                        case "s":
                            now = now.AddSeconds(num);
                            drift += num;
                            break;
                        case "m":
                            now = now.AddMinutes(num);
                            drift += num * 60;
                            break;
                        case "h":
                            now = now.AddHours(num);
                            drift += num * 60 * 60;
                            break;
                        case "d":
                            now = now.AddDays(num);
                            drift += num * 60 * 60 * 24;
                            break;
                    }
                }

                options.LoopEnd = now;

                if (drift == 0)
                {
                    Console.WriteLine("LoopEndTime is zero! Specify a real value");
                    return;
                }
            }
            
            options.CurrentUser = WindowsIdentity.GetCurrent().Name.Split('\\')[1];
            var nowtime = DateTime.Now;
            Console.WriteLine($"Initializing BloodHound at {nowtime.ToShortTimeString()} on {nowtime.ToShortDateString()}");
            Cache.CreateInstance(options);
            Utils.CreateInstance(options);

            if (!Utils.CheckWritePrivs())
            {
                Console.WriteLine("Unable to write in chosen directory. Please check privs");
                return;
            }

            SessionHelpers.Init(options);
            LocalAdminHelpers.Init();
            GroupHelpers.Init();
            AclHelpers.Init();
            DomainTrustEnumeration.Init();
            ContainerHelpers.Init();

            if (options.Test != null)
            {
                Test.DoStuff(options.Test);
                return;
            }

            //Lets test our connection to LDAP before we do anything else
            try
            {
                using (var conn = Utils.Instance.GetLdapConnection(options.Domain))
                {
                    if (conn == null)
                    {
                        Console.WriteLine("LDAP connection test failed, probably can't contact domain");
                        return;
                    }
                    conn.Bind();
                }
            }
            catch (LdapException)
            {
                Console.WriteLine("Ldap Connection Failure.");
                Console.WriteLine("Try again with the IgnoreLdapCert option if using SecureLDAP or check your DomainController/LdapPort option");
                return;
            }

            if (options.Uri != null)
            {
                if (!options.Uri.StartsWith("http",StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("URI must start with http:// or https://");
                    return;
                }

                using (var client = new WebClient())
                {
                    client.Headers.Add("content-type", "application/json");
                    client.Headers.Add("Accept", "application/json; charset=UTF-8");

                    if (options.UserPass != null)
                        client.Headers.Add("Authorization", options.GetEncodedUserPass());

                    try
                    {
                        client.DownloadData(options.GetCheckURI());
                        Console.WriteLine("Successfully connected to the Neo4j REST endpoint.");
                    }
                    catch
                    {
                        Console.WriteLine("Unable to connect to the Neo4j REST endpoint. Check your URI and username/password");
                        return;
                    }
                }
            }

            if (options.RemoveCSV && !options.CompressData)
            {
                Console.WriteLine("Ignoring RemoveCSV as CompressData is not set");
                options.RemoveCSV = false;
            }

            if (options.Stealth)
            {
                Console.WriteLine("Note: All stealth options are single threaded");
            }

            if (options.Throttle > 0)
            {
                Console.WriteLine(
                    $"Adding a delay of {options.Throttle} milliseconds to computer requests with a jitter of {options.Jitter}%");
            }

            foreach (var cmethod in collectionMethods)
            {
                options.CurrentCollectionMethod = cmethod;
                if (options.ComputerFile != null)
                {
                    if (!File.Exists(options.ComputerFile))
                    {
                        Console.WriteLine("Specified ComputerFile does not exist!");
                        return;
                    }

                    if (options.CurrentCollectionMethod.Equals(Default))
                    {
                        options.CurrentCollectionMethod = ComputerOnly;
                        Console.WriteLine("ComputerFile detected with default enumeration. Switching to ComputerOnly collection method");
                    }

                    if (!(options.CurrentCollectionMethod.Equals(Session) || options.CurrentCollectionMethod.Equals(SessionLoop) ||
                          options.CurrentCollectionMethod.Equals(LoggedOn) || options.CurrentCollectionMethod.Equals(LocalGroup) ||
                          options.CurrentCollectionMethod.Equals(ComputerOnly)))
                    {
                        Console.WriteLine("ComputerFile can only be used with the following collection methods: ComputerOnly, Session, SessionLoop, LocalGroup, LoggedOn");
                        continue;
                    }
                }

                if (options.CurrentCollectionMethod.Equals(LocalGroup) && options.Stealth)
                {
                    Console.WriteLine("Note: You specified Stealth and LocalGroup which is equivalent to GPOLocalGroup");
                    options.CurrentCollectionMethod = GPOLocalGroup;
                }

                var runner = new EnumerationRunner(options);

                if (options.CurrentCollectionMethod.Equals(SessionLoop))
                {
                    Console.WriteLine(options.MaxLoopTime == null
                        ? "Session Loop mode specified without MaxLoopTime, will loop indefinitely"
                        : $"Session Loop mode specified. Looping will end on {options.LoopEnd.ToShortDateString()} at {options.LoopEnd.ToShortTimeString()}");
                }

                if (options.Stealth)
                {
                    runner.StartStealthEnumeration();
                }
                else
                {
                    runner.StartEnumeration();
                }
                Console.WriteLine();
            }
            
            Cache.Instance.SaveCache();

            Utils.DeduplicateFiles();

            if (options.CompressData)
            {
                Utils.CompressFiles();
            }
        }

        public static void InvokeBloodHound(string[] args)
        {
            Main(args);
        }
    }
}
