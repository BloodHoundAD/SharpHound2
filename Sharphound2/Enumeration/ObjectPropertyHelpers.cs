using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using Sharphound2.JsonObjects;

namespace Sharphound2.Enumeration
{
    internal class ObjectPropertyHelpers
    {
        private static readonly DateTime Subt = new DateTime(1970,1,1);

        internal static void GetProps(SearchResultEntry entry, ResolvedEntry resolved, ref Domain obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ObjectProps))
            {
                return;
            }

            obj.Description = entry.GetProp("description");
        }

        internal static void GetProps(SearchResultEntry entry, ResolvedEntry resolved, ref Group obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ObjectProps))
            {
                return;
            }
            var ac = entry.GetProp("admincount");
            if (ac != null)
            {
                var a = int.Parse(ac);
                obj.AdminCount = a != 0;
            }
            else
            {
                obj.AdminCount = false;
            }

            obj.Description = entry.GetProp("description");
        }

        internal static void GetProps(SearchResultEntry entry, ResolvedEntry resolved, ref User obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ObjectProps))
            {
                return;
            }
            var uac = entry.GetProp("useraccountcontrol");
            bool enabled;
            if (int.TryParse(uac, out var flag))
            {
                var flags = (UacFlags)flag;
                enabled = (flags & UacFlags.AccountDisable) == 0;
            }
            else
            {
                enabled = true;
            }

            obj.Enabled = enabled;
            var history = entry.GetPropBytes("sidhistory");
            obj.SidHistory = history != null ? new SecurityIdentifier(history, 0).Value : "";
            obj.LastLogon = ConvertToUnixEpoch(entry.GetProp("lastlogon"));
            obj.PwdLastSet = ConvertToUnixEpoch(entry.GetProp("pwdlastset"));
            obj.ServicePrincipalNames = entry.GetPropArray("serviceprincipalname");
            obj.HasSpn = obj.ServicePrincipalNames.Length != 0;
            obj.DisplayName = entry.GetProp("displayname");
            obj.Email = entry.GetProp("mail");
            obj.Title = entry.GetProp("title");
            obj.HomeDirectory = entry.GetProp("homeDirectory");
            obj.Description = entry.GetProp("description");
            obj.UserPassword = entry.GetProp("userpassword");
            var ac = entry.GetProp("admincount");
            if (ac != null)
            {
                var a = int.Parse(ac);
                obj.AdminCount = a != 0;
            }
            else
            {
                obj.AdminCount = false;
            }
        }

        internal static void GetProps(SearchResultEntry entry, ResolvedEntry resolved, ref Computer obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ObjectProps))
            {
                return;
            }
            var uac = entry.GetProp("useraccountcontrol");
            bool enabled;
            bool unconstrained;
            if (int.TryParse(uac, out var flag))
            {
                var flags = (UacFlags)flag;
                enabled = (flags & UacFlags.AccountDisable) == 0;
                unconstrained = (flags & UacFlags.TrustedForDelegation) == UacFlags.TrustedForDelegation;
            }
            else
            {
                unconstrained = false;
                enabled = true;
            }

            obj.properties.Add("enabled", enabled);
            obj.properties.Add("unconstraineddelegation", unconstrained);
            obj.properties.Add("lastlogon", ConvertToUnixEpoch(entry.GetProp("lastlogon")));
            obj.properties.Add("pwdlastset", ConvertToUnixEpoch(entry.GetProp("pwdlastset")));
            var os = entry.GetProp("operatingsystem");
            var sp = entry.GetProp("operatingsystemservicepack");

            if (sp != null)
            {
                os = $"{os} {sp}";
            }

            obj.properties.Add("operatingsystem", os);
            obj.properties.Add("description", entry.GetProp("description"));
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
