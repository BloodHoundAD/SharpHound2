using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using System.Text;
using Sharphound2.OutputObjects;

namespace Sharphound2.Enumeration
{
    internal class ObjectPropertyHelpers
    {
        private static readonly DateTime Subt = new DateTime(1970,1,1);
        public void Init()
        {
            
        }

        public static ComputerProp GetComputerProps(SearchResultEntry entry, ResolvedEntry resolved)
        {
            var uac = entry.GetProp("useraccountcontrol");
            bool enabled;
            if (int.TryParse(uac, out var flag))
            {
                var flags = (UacFlags) flag;
                enabled = (flags & UacFlags.AccountDisable) == 0;
            }
            else
            {
                enabled = true;
            }
            var lastLogon = ConvertToUnixEpoch(entry.GetProp("lastlogon"));
            var lastSet = ConvertToUnixEpoch(entry.GetProp("pwdlastset"));
            var sid = entry.GetSid();
            var os = entry.GetProp("operatingsystem");
            var sp = entry.GetProp("operatingsystemservicepack");

            if (sp != null)
            {
                os = $"{os} {sp}";
            }

            return new ComputerProp
            {
                ComputerName = resolved.BloodHoundDisplay,
                Enabled = enabled,
                LastLogon = lastLogon,
                ObjectSid = sid,
                OperatingSystem = os,
                PwdLastSet = lastSet
            };
        }

        public static UserProp GetUserProps(SearchResultEntry entry, ResolvedEntry resolved)
        {
            var uac = entry.GetProp("useraccountcontrol");
            bool enabled;
            if (int.TryParse(uac, out var flag))
            {
                var flags = (UacFlags) flag;
                enabled = (flags & UacFlags.AccountDisable) == 0;
            }
            else
            {
                enabled = true;
            }
            var history = entry.GetPropBytes("sidhistory");
            var lastlogon = entry.GetProp("lastlogon");
            var pwdlastset = entry.GetProp("pwdlastset");
            var convertedlogon = ConvertToUnixEpoch(lastlogon);
            var convertedlastset = ConvertToUnixEpoch(pwdlastset);
            var sid = entry.GetSid();
            var sidhistory = history != null ? new SecurityIdentifier(history, 0).Value : "";

            return new UserProp
            {
                AccountName = resolved.BloodHoundDisplay,
                Enabled = enabled,
                LastLogon = convertedlogon,
                ObjectSid = sid,
                PwdLastSet = convertedlastset,
                SidHistory = sidhistory
            };
        }

        private static long ConvertToUnixEpoch(string ldapTime)
        {
            if (ldapTime == null)
                return -1;
            
            var time = long.Parse(ldapTime);
            if (time == 0)
                return 0;
            
            return (long)Math.Floor(DateTime.FromFileTimeUtc(time).Subtract(Subt).TotalSeconds);
        }

        [Flags]
        public enum UacFlags
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
