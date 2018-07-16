using System;
using System.DirectoryServices.Protocols;
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

            obj.Properties.Add("description",entry.GetProp("description"));
            var level = int.Parse(entry.GetProp("msds-behavior-version"));
            string func;
            switch (level)
            {
                case 0:
                    func = "2000 Mixed/Native";
                    break;
                case 1:
                    func = "2003 Interim";
                    break;
                case 2:
                    func = "2003";
                    break;
                case 3:
                    func = "2008";
                    break;
                case 4:
                    func = "2008 R2";
                    break;
                case 5:
                    func = "2012";
                    break;
                case 6:
                    func = "2012 R2";
                    break;
                case 7:
                    func = "2016";
                    break;
                default:
                    func = "Unknown";
                    break;
            }

            obj.Properties.Add("functionallevel", func);
        }

        internal static void GetProps(SearchResultEntry entry, ResolvedEntry resolved, ref Ou obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ObjectProps))
            {
                return;
            }

            obj.Properties.Add("description", entry.GetProp("description"));
            var opts = entry.GetProp("gpoptions");
            obj.Properties.Add("blocksinheritance", opts != null && opts.Equals("1"));
        }

        internal static void GetProps(SearchResultEntry entry, ResolvedEntry resolved, ref Gpo obj)
        {
            if (!Utils.IsMethodSet(ResolvedCollectionMethod.ObjectProps))
            {
                return;
            }

            obj.Properties.Add("description", entry.GetProp("description"));
            obj.Properties.Add("gpcpath", entry.GetProp("gpcfilesyspath"));
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
                obj.Properties.Add("admincount", a != 0);
            }
            else
            {
                obj.Properties.Add("admincount", false);
            }

            obj.Properties.Add("description", entry.GetProp("description"));
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

            obj.Properties.Add("enabled", enabled);
            //var history = entry.GetPropBytes("sidhistory");
            //obj.SidHistory = history != null ? new SecurityIdentifier(history, 0).Value : "";
            obj.Properties.Add("lastlogon", ConvertToUnixEpoch(entry.GetProp("lastlogon")));
            obj.Properties.Add("pwdlastset", ConvertToUnixEpoch(entry.GetProp("pwdlastset")));
            var spn = entry.GetPropArray("serviceprincipalname");
            obj.Properties.Add("serviceprincipalnames", spn);
            obj.Properties.Add("hasspn", spn.Length > 0);
            obj.Properties.Add("displayname", entry.GetProp("displayname"));
            obj.Properties.Add("email", entry.GetProp("mail"));
            obj.Properties.Add("title", entry.GetProp("title"));
            obj.Properties.Add("homedirectory", entry.GetProp("homedirectory"));
            obj.Properties.Add("description", entry.GetProp("description"));
            obj.Properties.Add("userpassword", entry.GetProp("userpassword"));
            var ac = entry.GetProp("admincount");
            if (ac != null)
            {
                var a = int.Parse(ac);
                obj.Properties.Add("admincount", a != 0);
            }
            else
            {
                obj.Properties.Add("admincount", false);
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

            obj.Properties.Add("enabled", enabled);
            obj.Properties.Add("unconstraineddelegation", unconstrained);
            obj.Properties.Add("lastlogon", ConvertToUnixEpoch(entry.GetProp("lastlogon")));
            obj.Properties.Add("pwdlastset", ConvertToUnixEpoch(entry.GetProp("pwdlastset")));
            obj.Properties.Add("serviceprincipalnames", entry.GetPropArray("serviceprincipalname"));
            var os = entry.GetProp("operatingsystem");
            var sp = entry.GetProp("operatingsystemservicepack");

            if (sp != null)
            {
                os = $"{os} {sp}";
            }

            obj.Properties.Add("operatingsystem", os);
            obj.Properties.Add("description", entry.GetProp("description"));
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
