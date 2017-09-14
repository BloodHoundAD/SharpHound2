using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Sharphound2.Enumeration;

namespace Sharphound2
{
    internal class Test
    {
        public static void DoStuff(string host)
        {
            //LocalAdminHelpers.LocalGroupApi("primary.testlab.local", "Administrators", "testlab.local", "");
            //LocalAdminHelpers.GetSamAdmins("primary.testlab.local", "S-1-5-21-883232822-274137685-4173207997");
            //Console.WriteLine("Test 1");
            //Console.WriteLine(Dns.GetHostEntry("windows1.testlab.local").Aliases[0]);
            //Console.WriteLine("Test 2");
            //LocalAdminHelpers.GetSamAdmins("primary.testlab.local");
            //Console.WriteLine("Test 3");
            //LocalAdminHelpers.GetSamAdmins("primary.testlab.local", "S-1-5-21-883232822-274137685-4173207997");

            //LocalAdminHelpers.GetSamAdmins("APL-DC27.dom1.jhuapl.edu", "APL-DC27");
            //LocalAdminHelpers.LocalGroupWinNt("primary", "Administrators");
            //var x = LocalAdminHelpers.GetSamAdmins(new ResolvedEntry
            //{
            //    BloodHoundDisplay = "\\\\primary",
            //    ComputerSamAccountName = "primary",
            //    ObjectType = "computer"
            //});

            //foreach (var y in x)
            //{
            //    Console.WriteLine(y.ToCsv());
            //}

            //Console.WriteLine(DnsManager.HostExists("abc123"));
            //Console.WriteLine(DnsManager.HostExistsDns("primary", out var realName));
            //Console.WriteLine(DnsManager.HostExists("primary.testlab.local"));


            var ldapFilter = "(samaccounttype=805306368)";
            var props = new[]
            {
                "samaccountname", "distinguishedname", "samaccounttype", "pwdlastset", "lastlogon", "sidhistory",
                "objectsid", "useraccountcontrol"
            };

            foreach (var result in Utils.Instance.DoSearch(ldapFilter, SearchScope.Subtree, props))
            {
                Console.WriteLine((UACFlags)int.Parse(result.GetProp("useraccountcontrol")));
            }
        }

        [Flags]
        public enum UACFlags
        {
            Script = 0x1,
            AccountDisable = 0x2,
            HomeDirRequired = 0x8,
            Lockout = 0x10,
            PasswordNotRequired = 0x20,
            PasswordCantChange = 0x40,
            EncryptedTextPwdAllowed = 0x80,
            TempDuplicateAccount = 0x100,
            NormalAccount = 0x200,
            InterdomainTrustAccount = 0x800,
            WorkstationTrustAccount = 0x1000,
            ServerTrustAccount = 0x2000,
            DontExpirePassword = 0x10000,
            MnsLogonAccount = 0x20000,
            SmartcardRequired = 0x40000,
            TrustedForDelegation = 0x80000,
            NotDelegated = 0x100000,
            UseDesKeyOnly = 0x200000,
            DontReqPreauth = 0x400000,
            PasswordExpired = 0x800000,
            TrustedToAuthForDelegation = 0x1000000,
            PartialSecretsAccount = 0x04000000
        }
    }
}
