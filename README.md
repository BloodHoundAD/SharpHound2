# SharpHound - C# Rewrite of the BloodHound Ingestor

## Get SharpHound
The latest build of SharpHound will always be in the BloodHound repository [here](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors)

## Compile Instructions
Sharphound is written using C# 7.0 features. To easily compile this project, use Visual Studio 2017. 

If you would like to compile on previous versions of Visual Studio, you can install the [Microsoft.Net.Compilers](https://www.nuget.org/packages/Microsoft.Net.Compilers/) nuget package.

Building the project will generate an executable as well as a PowerShell script that encapsulates the executable. All dependencies are rolled into the binary.

## Requirements
Sharphound is designed targetting .Net 3.5. Sharphound must be run from the context of a domain user, either directly through a logon or through another method such as RUNAS.

## More Information

## Usage
### Enumeration Options
* **CollectionMethod** - The collection method to use. This parameter accepts a comma separated list of values. Has the following potential values (Default: Default):
  * **Default** - Performs group membership collection, domain trust collection, local admin collection, and session collection
  * **Group** - Performs group membership collection
  * **LocalAdmin** - Performs local admin collection
  * **RDP** - Performs Remote Desktop Users collection
  * **DCOM** - Performs Distributed COM Users collection
  * **GPOLocalGroup** - Performs local admin collection using Group Policy Objects
  * **Session** - Performs session collection
  * **ComputerOnly** - Performs local admin, RDP, DCOM and session collection
  * **LoggedOn** - Performs privileged session collection (requires admin rights on target systems)
  * **Trusts** - Performs domain trust enumeration
  * **ACL** - Performs collection of ACLs
  * **Container** - Performs collection of Containers
  * **DcOnly** - Performs collection using LDAP only. Includes Group, Trusts, ACL, ObjectProps, Container, and GPOLocalGroup.
  * **All** - Performs all Collection Methods except GPOLocalGroup and LoggedOn
* **SearchForest** - Search all the domains in the forest instead of just your current one
* **Domain** - Search a particular domain. Uses your current domain if null (Default: null)
* **Stealth** - Performs stealth collection methods. All stealth options are single threaded.
* **SkipGCDeconfliction** - Skip Global Catalog deconfliction during session enumeration. This can speed up enumeration, but will result in possible inaccuracies in data.
* **ExcludeDc** - Excludes domain controllers from enumeration (avoids Microsoft ATA flags :) )
* **ComputerFile** - Specify a file to load computer names/IPs from
* **OU** - Specify which OU to enumerate

### Connection Options
* **DomainController** - Specify which Domain Controller to connect to (Default: null)
* **LdapPort** - Specify what port LDAP lives on (Default: 0)
* **SecureLdap** - Connect to AD using Secure LDAP instead of regular LDAP. Will connect to port 636 by default.
* **IgnoreLdapCert** - Ignores LDAP SSL certificate. Use if there's a self-signed certificate for example
* **LDAPUser** - Username to connect to LDAP with. Requires the LDAPPassword parameter as well (Default: null)
* **LDAPPass** - Password for the user to connect to LDAP with. Requires the LDAPUser parameter as well (Default: null)
* **DisableKerbSigning** - Disables LDAP encryption. Not recommended.

### Performance Options
* **Threads** - Specify the number of threads to use (Default: 10)
* **PingTimeout** - Specifies the timeout for ping requests in milliseconds (Default: 250)
* **SkipPing** - Instructs Sharphound to skip ping requests to see if systems are up
* **LoopDelay** - The number of seconds in between session loops (Default: 300)
* **MaxLoopTime** - The amount of time to continue session looping. Format is 0d0h0m0s. Null will loop for two hours. (Default: 2h)
* **Throttle** - Adds a delay after each request to a computer. Value is in milliseconds (Default: 0)
* **Jitter** - Adds a percentage jitter to throttle. (Default: 0)

### Output Options
* **JSONFolder** - Folder in which to store JSON files (Default: .)
* **JSONPrefix** - Prefix to add to your JSON files (Default: "")
* **NoZip** - Don't compress JSON files to the zip file. Leaves JSON files on disk. (Default: false)
* **EncryptZip** - Add a randomly generated password to the zip file.
* **ZipFileName** - Specify the name of the zip file
* **RandomFilenames** - Randomize output file names
* **PrettyJson** - Outputs JSON with indentation on multiple lines to improve readability. Tradeoff is increased file size.

### Cache Options
* **CacheFile** - Filename for the Sharphound cache. (Default: BloodHound.bin)
* **NoSaveCache** - Don't save the cache file to disk. Without this flag, BloodHound.bin will be dropped to disk
* **Invalidate** - Invalidate the cache file and build a new cache

### Misc Options
* **StatusInterval** - Interval to display progress during enumeration in milliseconds (Default: 30000)
* **Verbose** - Enables verbose output
