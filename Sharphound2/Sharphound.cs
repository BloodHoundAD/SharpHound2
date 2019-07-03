using CommandLine;
using Sharphound2.Enumeration;
using System;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;
using CommandLine.Text;
using static Sharphound2.CollectionMethod;

namespace Sharphound2
{
    internal class Sharphound
    {
        public class Options
        {
            [OptionArray('c', "CollectionMethod", DefaultValue = new[] { "Default" }, HelpText = "Collection Method (Group, LocalGroup, GPOLocalGroup, Session, LoggedOn, ComputerOnly, Trusts, Stealth, Default, RDP, DCOM")]
            public string[] CollectionMethod { get; set; }

            [Option(HelpText = "Use stealth enumeration options", DefaultValue = false)]
            public bool Stealth { get; set; }

            [Option('d', "Domain", HelpText = "Domain to enumerate", DefaultValue = null, MutuallyExclusiveSet = "DomainOption")]
            public string Domain { get; set; }

            [Option('s', "SearchForest", HelpText = "Search the entire forest", DefaultValue = false, MutuallyExclusiveSet = "DomainOption")]
            public bool SearchForest { get; set; }

            [Option(DefaultValue = null)]
            public string Ou { get; set; }

            [Option(HelpText = "Custom LDAP filter to control collection", DefaultValue = null)]
            public string LdapFilter { get; set; }

            [Option(DefaultValue = null)]
            public string ComputerFile { get; set; }

            [Option('t', "Threads", HelpText = "Number of Threads to use", DefaultValue = 10)]
            public int Threads { get; set; }

            [Option(HelpText = "Folder to drop Json files", DefaultValue = ".")]
            public string JsonFolder { get; set; }

            [Option(HelpText = "Prefix for Json file names", DefaultValue = "")]
            public string JsonPrefix { get; set; }

            [Option(DefaultValue = false)]
            public bool PrettyJson { get; set; }

            [Option(DefaultValue = 0)]
            public int LdapPort { get; set; }

            [Option(HelpText = "Interval to display progress in milliseconds", DefaultValue = 30000)]
            public int StatusInterval { get; set; }

            [Option(HelpText = "Skip ping checks for hosts", DefaultValue = false)]
            public bool SkipPing { get; set; }

            [Option(HelpText = "Timeout in milliseconds for ping timeout", DefaultValue = 500)]
            public int PingTimeout { get; set; }

            [Option(HelpText = "Skip Global Catalog Deconfliction", DefaultValue = false)]
            public bool SkipGcDeconfliction { get; set; }

            [Option(HelpText = "Filename for the data cache (defaults to b64 of machine sid)", DefaultValue = null)]
            public string CacheFile { get; set; }

            [Option(HelpText = "Filename for the zip file", DefaultValue = null)]
            public string ZipFileName { get; set; }

            [Option(HelpText = "Random Filenames", DefaultValue = false)]
            public bool RandomFilenames { get; set; }

            [Option(HelpText = "Invalidate and build new cache", DefaultValue = false)]
            public bool Invalidate { get; set; }

            [Option(HelpText = "Don't save the cache file to disk", DefaultValue = false)]
            public bool NoSaveCache { get; set; }

            [Option(DefaultValue = 300, HelpText = "Time in seconds between each session loop")]
            public int LoopDelay { get; set; }

            [Option(DefaultValue = null)]
            public string MaxLoopTime { get; set; }

            [Option('v', "Verbose", HelpText = "Enable verbose output", DefaultValue = false)]
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
            public bool NoZip { get; set; }

            [Option(DefaultValue = false)]
            public bool EncryptZip { get; set; }

            [Option(DefaultValue = null)]
            public string Test { get; set; }

            [Option(DefaultValue = null)]
            public string DomainController { get; set; }

            [Option(DefaultValue = false)]
            public bool Debug { get; set; }

            [Option(DefaultValue = 0)]
            public int Throttle { get; set; }

            [Option(DefaultValue = 0)]
            public int Jitter { get; set; }

            [Option(DefaultValue = null)]
            public string LdapUser { get; set; }

            [Option(DefaultValue = null)]
            public string LdapPass { get; set; }

            [Option(DefaultValue = null)]
            public string OverrideUser { get; set; }

            [ParserState]
            public IParserState LastParserState { get; set; }

            [HelpOption]
            public string GetUsage()
            {
                var text = @"SharpHound v2.1.0
Usage: SharpHound.exe <options>

Enumeration Options:
    -c , --CollectionMethod (Default: Default)
        Default - Enumerate Trusts, Sessions, Local Admin, and Group Membership
        Group - Enumerate Group Membership
        LocalGroup - Enumerate the Administrators, Distributed COM Users, and Remote Desktop Users groups
        LocalAdmin - Enumerate the Administrators Group
        DCOM - Enumerate the Distributed COM Users Group
        RDP - Enumerate the Remote Desktop Users Group
        Session - Enumerate Sessions
        SessionLoop - Continuously Enumerate Sessions
        LoggedOn - Enumerate Sessions using Elevation
        ComputerOnly - Enumerate Sessions and Local Admin
        Trusts - Enumerate Domain Trusts
        ACL - Enumerate ACLs
        ObjectProps - Enumerate Object Properties for Users/Computers
        Container - Collects GPO/OU Structure
        DCOnly - Enumerate Group Membership, Trusts, ACLs, ObjectProps, Containers, and GPO Local Admins
        All - Performs all enumeration methods except GPOLocalGroup and LoggedOn

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
        Session, SessionLoop, LocalAdmin, ComputerOnly, LoggedOn

    --ExcludeDC
        Exclude domain controllers from session queries. Useful for ATA environments which detect this behavior

    --LdapFilter
        Append this to the ldap filter used for querying the directory

    --OverrideUser
        Overrides the 'current' user to filter it out of session enumeration.
        Useful when you're using runas, as the user will be detected incorrectly
   
Connection Options:
    --SecureLdap
        Uses secure LDAP (LDAPS) instead of regular

    --LdapPort
        Override the port used to connect to LDAP

    --IgnoreLdapCert
        Ignores the SSL certificate for LDAP. Use for self-signed certs

    --DisableKerbSigning
        Disables Kerberos signing on LDAP requests

    --DomainController (Default: null)
        Specify which Domain Controller to request data from. Defaults to closest DC using Site Names

    --LdapUser (Default: null)
        User to connect to LDAP with

    --LdapPass (Default: null)
        Password for the user to connect to LDAP with

Performance Tuning:
    -t , --Threads (Default: 10)
        The number of threads to use for Enumeration
    
    --PingTimeout (Default: 200)
        Timeout to use when pinging computers in milliseconds

    --SkipPing
        Skip pinging computers (will most likely be slower)
        Use this option if ping is disabled on the network

    --LoopDelay
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
    --JsonFolder (Default: .)
        The folder in which to store JSON files

    --JsonPrefix (Default: """")
        The prefix to add to your JSON files

    --NoZip
        Don't compress and remove JSON files

    --EncryptZip
        Add a random password to the zip files

    --ZipFileName
        Specify the filename for the zip file

    -- RandomFilenames
        Randomize output filenames

    --PrettyJson
        Output pretty JSON

Cache Options
    --NoSaveCache
        Dont save the cache to disk to speed up future runs

    --CacheFile (Default: <B64 Machine Sid>.bin)
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

            public ResolvedCollectionMethod ResolvedCollMethods { get; set; }
            public string CurrentUser { get; set; }

            public DateTime LoopEnd { get; set; }
            public bool SessionLoopRunning = false;

            //public string GetEncodedUserPass()
            //{
            //    var plainTextBytes = Encoding.UTF8.GetBytes(UserPass);
            //    return Convert.ToBase64String(plainTextBytes);
            //}

            //public string GetURI()
            //{
            //    return $"{Uri}/db/data/transaction/commit";
            //}

            //public string GetCheckURI()
            //{
            //    return $"{Uri}/db/data/";
            //}
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

            if (options.CacheFile == null)
            {
                var sid = Utils.GetLocalMachineSid();
                var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(sid);
                options.CacheFile = $"{Convert.ToBase64String(plainTextBytes)}.bin";
            }

            try
            {
                // ReSharper disable once ReturnValueOfPureMethodIsNotUsed
                Path.Combine(options.JsonFolder, options.CacheFile);
            }
            catch (ArgumentException)
            {
                Console.WriteLine("Invalid characters in output path. Check for trailing backslashes!");
                return;
            }

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

            var resolved = ResolvedCollectionMethod.None;

            foreach (var unparsed in options.CollectionMethod)
            {
                try
                {
                    var e = (CollectionMethod)Enum.Parse(typeof(CollectionMethod), unparsed, true);
                    switch (e)
                    {
                        case All:
                            resolved = resolved | ResolvedCollectionMethod.ACL | ResolvedCollectionMethod.Container |
                                       ResolvedCollectionMethod.Group | ResolvedCollectionMethod.LocalAdmin |
                                       ResolvedCollectionMethod.ObjectProps | ResolvedCollectionMethod.RDP |
                                       ResolvedCollectionMethod.Session | ResolvedCollectionMethod.Trusts |
                                       ResolvedCollectionMethod.DCOM | ResolvedCollectionMethod.LoggedOn |
                                       ResolvedCollectionMethod.SPNTargets;
                            break;
                        case DcOnly:
                            resolved = resolved | ResolvedCollectionMethod.ACL | ResolvedCollectionMethod.Container |
                                       ResolvedCollectionMethod.Trusts | ResolvedCollectionMethod.ObjectProps |
                                       ResolvedCollectionMethod.GPOLocalGroup | ResolvedCollectionMethod.Group | ResolvedCollectionMethod.DCOnly;
                            break;
                        case CollectionMethod.Group:
                            resolved = resolved | ResolvedCollectionMethod.Group;
                            break;
                        case ComputerOnly:
                            resolved = resolved | ResolvedCollectionMethod.LocalAdmin |
                                       ResolvedCollectionMethod.Session | ResolvedCollectionMethod.RDP |
                                       ResolvedCollectionMethod.DCOM;
                            break;
                        case LocalGroup:
                            resolved = resolved | ResolvedCollectionMethod.LocalAdmin | ResolvedCollectionMethod.RDP | ResolvedCollectionMethod.DCOM;
                            break;
                        case GPOLocalGroup:
                            resolved = resolved | ResolvedCollectionMethod.GPOLocalGroup;
                            break;
                        case Session:
                            resolved = resolved | ResolvedCollectionMethod.Session;
                            break;
                        case LoggedOn:
                            resolved = resolved | ResolvedCollectionMethod.LoggedOn;
                            break;
                        case Trusts:
                            resolved = resolved | ResolvedCollectionMethod.Trusts;
                            break;
                        case ACL:
                            resolved = resolved | ResolvedCollectionMethod.ACL;
                            break;
                        case SessionLoop:
                            resolved = resolved | ResolvedCollectionMethod.SessionLoop;
                            break;
                        case Default:
                            resolved = resolved | ResolvedCollectionMethod.RDP | ResolvedCollectionMethod.DCOM | ResolvedCollectionMethod.LocalAdmin | ResolvedCollectionMethod.Group | ResolvedCollectionMethod.Session | ResolvedCollectionMethod.Trusts;
                            break;
                        case ObjectProps:
                            resolved = resolved | ResolvedCollectionMethod.ObjectProps;
                            break;
                        case Container:
                            resolved = resolved | ResolvedCollectionMethod.Container;
                            break;
                        case LocalAdmin:
                            resolved = resolved | ResolvedCollectionMethod.LocalAdmin;
                            break;
                        case RDP:
                            resolved = resolved | ResolvedCollectionMethod.RDP;
                            break;
                        case DCOM:
                            resolved = resolved | ResolvedCollectionMethod.DCOM;
                            break;
                        case SPNTargets:
                            resolved = resolved | ResolvedCollectionMethod.SPNTargets;
                            break;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }
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
                //options.Threads = 1;
            }

            if ((resolved & ResolvedCollectionMethod.SessionLoop) != 0)
            {
                if (options.MaxLoopTime != null)
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
                else
                {
                    options.LoopEnd = DateTime.Now + TimeSpan.FromHours(2);
                }
            }

            options.CurrentUser = options.OverrideUser ?? WindowsIdentity.GetCurrent().Name.Split('\\')[1];

            Cache.CreateInstance(options);
            Utils.CreateInstance(options);


            if (!Utils.CheckWritePrivs())
            {
                Console.WriteLine("Unable to write in chosen directory. Please check privs");
                return;
            }

            var nowtime = DateTime.Now;
            Console.WriteLine($"Initializing BloodHound at {nowtime.ToShortTimeString()} on {nowtime.ToShortDateString()}");

            if (options.ComputerFile != null)
            {
                if (options.PingTimeout < 1000)
                {
                    Console.WriteLine("Increasing ping timeout to 1 second for ComputerFile mode");
                    options.PingTimeout = 1000;
                }
            }

            if (Utils.Instance.GetDomainList().Count == 0)
            {
                Console.WriteLine("Unable to contact domain. Try from a domain context!");
                return;
            }

            if (options.DomainController != null)
            {
                Console.WriteLine("Manually specifying a domain controller will likely result in data loss. Only use this for performance/opsec reasons");
                if (options.SearchForest)
                {
                    Console.WriteLine("SearchForest is not usable with the --DomainController flag");
                    options.SearchForest = false;
                }
            }
            else
            {
                //Build our DC cache
                Utils.Instance.GetUsableDomainControllers();
            }

            SessionHelpers.Init(options);
            LocalGroupHelpers.Init(options);
            GroupHelpers.Init();
            AclHelpers.Init();
            TrustHelpers.Init();
            ContainerHelpers.Init();

            if (options.Test != null)
            {
                Test.DoStuff(options.Test);
                return;
            }

            //Lets test our connection to LDAP before we do anything else
            try
            {
                var conn = Utils.Instance.GetLdapConnection(options.Domain);
                if (conn == null)
                {
                    Console.WriteLine("LDAP connection test failed, probably can't contact domain");
                    return;
                }
                conn.Bind();
            }
            catch (LdapException)
            {
                Console.WriteLine("Ldap Connection Failure.");
                if (options.LdapPass != null)
                {
                    Console.WriteLine("Check credentials supplied to SharpHound");
                }
                Console.WriteLine("Try again with the IgnoreLdapCert option if using SecureLDAP or check your DomainController/LdapPort option");
                return;
            }

            //if (options.Uri != null)
            //{
            //    if (!options.Uri.StartsWith("http",StringComparison.OrdinalIgnoreCase))
            //    {
            //        Console.WriteLine("URI must start with http:// or https://");
            //        return;
            //    }

            //    using (var client = new WebClient())
            //    {
            //        client.Headers.Add("content-type", "application/json");
            //        client.Headers.Add("Accept", "application/json; charset=UTF-8");

            //        if (options.UserPass != null)
            //            client.Headers.Add("Authorization", options.GetEncodedUserPass());

            //        try
            //        {
            //            client.DownloadData(options.GetCheckURI());
            //            Console.WriteLine("Successfully connected to the Neo4j REST endpoint.");
            //            Console.WriteLine("WARNING: As of BloodHound 1.5, using the REST API is unsupported and will be removed in a future release.");
            //            Console.WriteLine("WARNING: Container collection will not work with the REST API, and bugs may exist.");
            //        }
            //        catch
            //        {
            //            Console.WriteLine("Unable to connect to the Neo4j REST endpoint. Check your URI and username/password");
            //            Console.WriteLine("WARNING: As of BloodHound 1.5, using the REST API is unsupported and will be removed in a future release.");
            //            Console.WriteLine("WARNING: Container collection will not work with the REST API, and bugs may exist.");
            //            return;
            //        }
            //    }
            //}

            if (options.Stealth)
            {
                Console.WriteLine("Note: All stealth options are single threaded");
            }

            if (options.Throttle > 0)
            {
                Console.WriteLine(
                    $"Adding a delay of {options.Throttle} milliseconds to computer requests with a jitter of {options.Jitter}%");
            }

            //Do some sanity checks
            if (options.ComputerFile != null)
            {
                if (!File.Exists(options.ComputerFile))
                {
                    Console.WriteLine("Specified ComputerFile does not exist!");
                    return;
                }

                if (options.Stealth)
                {
                    Console.WriteLine("Switching to one thread for ComputerFile, removing stealth");
                    options.Stealth = false;
                    options.Threads = 1;
                }

                Console.WriteLine("ComputerFile detected! Removing non-computer collection methods");
                resolved = resolved & ~ResolvedCollectionMethod.ACL & ~ResolvedCollectionMethod.Group
                           & ~ResolvedCollectionMethod.GPOLocalGroup & ~ResolvedCollectionMethod.Trusts
                           & ~ResolvedCollectionMethod.Container & ~ResolvedCollectionMethod.ObjectProps;
            }

            if (options.Stealth)
            {
                if ((resolved & ResolvedCollectionMethod.LocalAdmin) != 0)
                {
                    Console.WriteLine("Note: You specified Stealth and LocalGroup which is equivalent to GPOLocalGroup");
                    resolved = resolved & ~ResolvedCollectionMethod.LocalAdmin;
                    resolved = resolved | ResolvedCollectionMethod.GPOLocalGroup;
                }

                if ((resolved & ResolvedCollectionMethod.LoggedOn) != 0)
                {
                    Console.WriteLine("LoggedOn enumeration is not supported with Stealth");
                    resolved = resolved & ~ResolvedCollectionMethod.LoggedOn;
                }
            }

            if ((resolved & ResolvedCollectionMethod.Session) != 0 &&
                (resolved & ResolvedCollectionMethod.SessionLoop) != 0)
            {
                resolved = resolved ^ ResolvedCollectionMethod.Session;
            }

            if ((resolved & ResolvedCollectionMethod.LoggedOn) != 0 &&
                (resolved & ResolvedCollectionMethod.SessionLoop) != 0)
            {
                resolved = resolved ^ ResolvedCollectionMethod.LoggedOn;
                resolved = resolved | ResolvedCollectionMethod.LoggedOnLoop;
            }


            if ((resolved & ResolvedCollectionMethod.SessionLoop) != 0)
            {
                Console.WriteLine(options.MaxLoopTime == null
                    ? $"Session Loop mode specified without MaxLoopTime, will loop for 2 hours ({options.LoopEnd.ToShortDateString()} at {options.LoopEnd.ToShortTimeString()})"
                    : $"Session Loop mode specified. Looping will end on {options.LoopEnd.ToShortDateString()} at {options.LoopEnd.ToShortTimeString()}");
                Console.WriteLine("Looping will start after any other collection methods");
            }

            if (resolved.Equals(ResolvedCollectionMethod.None))
            {
                Console.WriteLine("No collection methods specified. Exiting");
                return;
            }

            Console.WriteLine($"Resolved Collection Methods to {resolved}");

            if ((resolved & ResolvedCollectionMethod.ACL) != 0)
            {
                Utils.Verbose("Building GUID Cache");
                AclHelpers.BuildGuidCache();
            }

            options.ResolvedCollMethods = resolved;

            var runner = new EnumerationRunner(options);

            if (options.Stealth)
            {
                runner.StartStealthEnumeration();
            }
            else
            {
                if (options.ComputerFile == null)
                {
                    runner.StartEnumeration();
                }
                else
                {
                    runner.StartCompFileEnumeration();
                }
            }
            Console.WriteLine();

            Cache.Instance.SaveCache();
            Utils.Instance.KillConnections();

            if (!options.NoZip)
            {
                Utils.CompressFiles();
            }
        }

        // Accessor function for the PS1 to work, do not change or remove
        public static void InvokeBloodHound(string[] args)
        {
            Main(args);
        }
    }
}
