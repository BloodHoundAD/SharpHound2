# SharpHound - C# Rewrite of the BloodHound Ingestor

This project is still in beta. You have been warned!

## Compile Instructions
Sharphound is written using C# 7.0 features. To easily compile this project, use Visual Studio 2017. 

If you would like to compile on previous versions of Visual Studio, you can install the [Microsoft.Net.Compilers](https://www.nuget.org/packages/Microsoft.Net.Compilers/) nuget package.

Building the project will generate an executable as well as a PowerShell script that encapsulates the executable. All dependencies are rolled into the binary.

## Requirements
Sharphound is designed targetting .Net 3.5. Sharphound must be run from the context of a domain user, either directly through a logon or through another method such as RUNAS.

## More Information

## Usage
### Enumeration Options
* **CollectionMethod** - The collection method to use. This parameter will accept a comma seperated list of values. Has the following potential values (Default: Default):
   * **Default** - Performs group membership collection, domain trust collection, local admin collection, and session collection
   * **Group** - Performs group membership collection only
   * **LocalGroup** - Performs local admin collection only
   * **GPOLocalGroup** - Performs local admin collection using Group Policy Objects
   * **Session** - Performs session collection only
   * **ComputerOnly** - Performs local admin collection and session collection
   * **LoggedOn** - Performs privileged session collection (requires admin rights on target systems)
   * **Trusts** - Performs domain trust enumeration for the specified domain
   * **ACL** - Performs collection of ACLs

* **SearchForest** - Search all the domains in the forest instead of just your current one
* **Domain** - Search a particular domain. Uses your current domain if null (Default: null)
* **Stealth** - Performs stealth collection methods. All stealth options are single threaded.
* **SkipGCDeconfliction** - Skip Global Catalog deconfliction during session enumeration. This can speed up enumeration, but will result in possible inaccuracies in data.
* **ExcludeDc** - Excludes domain controllers from session enumeration (avoids Microsoft ATA flags :) )

### Connection Options
* **SecureLdap** - Connect to AD using Secure LDAP instead of plaintext LDAP.
* **IgnoreLdapCert** - Ignores LDAP SSL certificate. Use if there's a self-signed certificate for example

### Performance Options
* **Threads** - Specify the number of threads to use (Default: 10)
* **PingTimeout** - Specifies the timeout for ping requests in milliseconds (Default: 250)
* **SkipPing** - Instructs Sharphound to skip ping requests to see if systems are up
* **LoopTime** - The number of minutes in between session loops (Default: 5)
* **MaxLoopTime** - The amount of time to continue session looping. Format is 0d0h0m0s. Null will result in infinite looping (Default: null)
* **Throttle** - Adds a delay after each request to a computer. Value is in milliseconds (Default: 0)
* **Jitter** - Adds a percentage jitter to throttle. (Default: 0)

### Output Options
* **CSVFolder** - Folder in which to store CSV files (Default: .)
* **CSVPrefix** - Prefix to add to your CSV files (Default: "")
* **Uri** - Url for the Neo4j REST API. Format is SERVER:PORT (Default: null)
* **UserPass** - Username and password for the Neo4j REST API. Format is username:password (Default: null)
* **CompressData** - Compresses CSV files to a single zip file after completion of enumeration
* **RemoveCSV** - Deletes CSV files from disk after run. Only usable with the **CompressData** flag

### Cache Options
* **CacheFile** - Filename for the Sharphound cache. (Default: BloodHound.bin)
* **NoSaveCache** - Don't save the cache file to disk. Without this flag, BloodHound.bin will be dropped to disk
* **Invalidate** - Invalidate the cache file and build a new cache

### Misc Options
* **StatusInterval** - Interval to display progress during enumeration in milliseconds (Default: 30000)
* **Verbose** - Enables verbose output
