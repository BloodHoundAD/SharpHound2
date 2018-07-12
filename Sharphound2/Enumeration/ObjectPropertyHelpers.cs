using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using Sharphound2.JsonObjects;
using Sharphound2.OutputObjects;

namespace Sharphound2.Enumeration
{
    internal class ObjectPropertyHelpers
    {
        private static readonly DateTime Subt = new DateTime(1970,1,1);
        private static Utils _utils;

        public static void Init()
        {
            _utils = Utils.Instance;
        }

        internal static void GetProps(SearchResultEntry entry, ResolvedEntry resolved, ref Domain obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ObjectProps))
            {
                return;
            }

            obj.Description = entry.GetProp("description");
        }

        internal static void GetProps(SearchResultEntry entry, ResolvedEntry resolved, ref Group groupObj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ObjectProps))
            {
                return;
            }
            var ac = entry.GetProp("admincount");
            if (ac != null)
            {
                var a = int.Parse(ac);
                groupObj.AdminCount = a != 0;
            }
            else
            {
                groupObj.AdminCount = false;
            }

            groupObj.Description = entry.GetProp("description");
        }

        internal static void GetProps(SearchResultEntry entry, ResolvedEntry resolved, ref User userObj)
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

            userObj.Enabled = enabled;
            var history = entry.GetPropBytes("sidhistory");
            userObj.SidHistory = history != null ? new SecurityIdentifier(history, 0).Value : "";
            userObj.LastLogon = ConvertToUnixEpoch(entry.GetProp("lastlogon"));
            userObj.PwdLastSet = ConvertToUnixEpoch(entry.GetProp("pwdlastset"));
            userObj.ServicePrincipalNames = entry.GetPropArray("serviceprincipalname");
            userObj.HasSpn = userObj.ServicePrincipalNames.Length != 0;
            userObj.DisplayName = entry.GetProp("displayname");
            userObj.Email = entry.GetProp("mail");
            userObj.Title = entry.GetProp("title");
            userObj.HomeDirectory = entry.GetProp("homeDirectory");
            userObj.Description = entry.GetProp("description");
            userObj.UserPassword = entry.GetProp("userpassword");
            var ac = entry.GetProp("admincount");
            if (ac != null)
            {
                var a = int.Parse(ac);
                userObj.AdminCount = a != 0;
            }
            else
            {
                userObj.AdminCount = false;
            }
        }

        internal static void GetProps(SearchResultEntry entry, ResolvedEntry resolved, ref Computer compObj)
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

            compObj.Enabled = enabled;
            compObj.UnconstrainedDelegation = unconstrained;
            compObj.LastLogon = ConvertToUnixEpoch(entry.GetProp("lastlogon"));
            compObj.PwdLastSet = ConvertToUnixEpoch(entry.GetProp("pwdlastset"));
            var os = entry.GetProp("operatingsystem");
            var sp = entry.GetProp("operatingsystemservicepack");
            var domainS = resolved.BloodHoundDisplay.Split('.');
            domainS = domainS.Skip(1).ToArray();
            compObj.Domain = string.Join(".", domainS).ToUpper();

            if (sp != null)
            {
                os = $"{os} {sp}";
            }

            compObj.OperatingSystem = os;
            compObj.Description = entry.GetProp("description");
        }

        public static ComputerProp GetComputerProps(SearchResultEntry entry, ResolvedEntry resolved)
        {
            var uac = entry.GetProp("useraccountcontrol");
            bool enabled;
            bool unconstrained;
            if (int.TryParse(uac, out var flag))
            {
                var flags = (UacFlags) flag;
                enabled = (flags & UacFlags.AccountDisable) == 0;
                unconstrained = (flags & UacFlags.TrustedForDelegation) == UacFlags.TrustedForDelegation;
            }
            else
            {
                unconstrained = false;
                enabled = true;
            }
            var lastLogon = ConvertToUnixEpoch(entry.GetProp("lastlogon"));
            var lastSet = ConvertToUnixEpoch(entry.GetProp("pwdlastset"));
            var sid = entry.GetSid();
            var os = entry.GetProp("operatingsystem");
            var sp = entry.GetProp("operatingsystemservicepack");
            var domainS = resolved.BloodHoundDisplay.Split('.');
            domainS = domainS.Skip(1).ToArray();
            var domain = string.Join(".", domainS).ToUpper();

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
                PwdLastSet = lastSet,
                UnconstrainedDelegation = unconstrained,
                Domain = domain
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
            var spn = entry.GetPropArray("serviceprincipalname");
            var displayName = entry.GetProp("displayname");
            var hasSpn = spn.Length != 0;
            var spnString = string.Join("|", spn);
            var convertedlogon = ConvertToUnixEpoch(lastlogon);
            var convertedlastset = ConvertToUnixEpoch(pwdlastset);
            var sid = entry.GetSid();
            var sidhistory = history != null ? new SecurityIdentifier(history, 0).Value : "";
            var mail = entry.GetProp("mail");
            var domain = resolved.BloodHoundDisplay.Split('@')[1].ToUpper();
            var title = entry.GetProp("title");
            var homedir = entry.GetProp("homeDirectory");

            return new UserProp
            {
                AccountName = resolved.BloodHoundDisplay,
                Enabled = enabled,
                LastLogon = convertedlogon,
                ObjectSid = sid,
                PwdLastSet = convertedlastset,
                SidHistory = sidhistory,
                HasSpn = hasSpn,
                ServicePrincipalNames = spnString,
                DisplayName = displayName,
                Email = mail,
                Domain = domain,
                Title = title,
                HomeDirectory = homedir
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
