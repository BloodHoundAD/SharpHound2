namespace Sharphound2.Enumeration
{
    internal class MappedPrincipal
    {
        private string _principalName;
        private string _objectType;

        public string PrincipalName
        {
            get => _principalName.ToUpper();
            set => _principalName = value;
        }

        public string ObjectType
        {
            get => _objectType.ToLower();
            set => _objectType = value;
        }

        public MappedPrincipal(string name, string type)
        {
            PrincipalName = name;
            ObjectType = type;
        }

        public static bool GetCommon(string sid, out MappedPrincipal result)
        {
            switch (sid)
            {
                case "S-1-0":
                    result = new MappedPrincipal("Null Authority", "USER");
                    break;
                case "S-1-0-0":
                    result = new MappedPrincipal("Nobody", "USER");
                    break;
                case "S-1-1":
                    result = new MappedPrincipal("World Authority", "USER");
                    break;
                case "S-1-1-0":
                    result = new MappedPrincipal("Everyone", "GROUP");
                    break;
                case "S-1-2":
                    result = new MappedPrincipal("Local Authority", "USER");
                    break;
                case "S-1-2-0":
                    result = new MappedPrincipal("Local", "GROUP");
                    break;
                case "S-1-2-1":
                    result = new MappedPrincipal("Console Logon", "GROUP");
                    break;
                case "S-1-3":
                    result = new MappedPrincipal("Creator Authority", "USER");
                    break;
                case "S-1-3-0":
                    result = new MappedPrincipal("Creator Owner", "USER");
                    break;
                case "S-1-3-1":
                    result = new MappedPrincipal("Creator Group", "GROUP");
                    break;
                case "S-1-3-2":
                    result = new MappedPrincipal("Creator Owner Server", "COMPUTER");
                    break;
                case "S-1-3-3":
                    result = new MappedPrincipal("Creator Group Server", "COMPUTER");
                    break;
                case "S-1-3-4":
                    result = new MappedPrincipal("Owner Rights", "GROUP");
                    break;
                case "S-1-4":
                    result = new MappedPrincipal("Non-unique Authority", "USER");
                    break;
                case "S-1-5":
                    result = new MappedPrincipal("NT Authority", "USER");
                    break;
                case "S-1-5-1":
                    result = new MappedPrincipal("Dialup", "GROUP");
                    break;
                case "S-1-5-2":
                    result = new MappedPrincipal("Network", "GROUP");
                    break;
                case "S-1-5-3":
                    result = new MappedPrincipal("Batch", "GROUP");
                    break;
                case "S-1-5-4":
                    result = new MappedPrincipal("Interactive", "GROUP");
                    break;
                case "S-1-5-6":
                    result = new MappedPrincipal("Service", "GROUP");
                    break;
                case "S-1-5-7":
                    result = new MappedPrincipal("Anonymous", "GROUP");
                    break;
                case "S-1-5-8":
                    result = new MappedPrincipal("Proxy", "GROUP");
                    break;
                case "S-1-5-9":
                    result = new MappedPrincipal("Enterprise Domain Controllers", "GROUP");
                    break;
                case "S-1-5-10":
                    result = new MappedPrincipal("Principal Self", "USER");
                    break;
                case "S-1-5-11":
                    result = new MappedPrincipal("Authenticated Users", "GROUP");
                    break;
                case "S-1-5-12":
                    result = new MappedPrincipal("Restricted Code", "GROUP");
                    break;
                case "S-1-5-13":
                    result = new MappedPrincipal("Terminal Server Users", "GROUP");
                    break;
                case "S-1-5-14":
                    result = new MappedPrincipal("Remote Interactive Logon", "GROUP");
                    break;
                case "S-1-5-15":
                    result = new MappedPrincipal("This Organization ", "GROUP");
                    break;
                case "S-1-5-17":
                    result = new MappedPrincipal("This Organization ", "GROUP");
                    break;
                case "S-1-5-18":
                    result = new MappedPrincipal("Local System", "USER");
                    break;
                case "S-1-5-19":
                    result = new MappedPrincipal("NT Authority", "USER");
                    break;
                case "S-1-5-20":
                    result = new MappedPrincipal("NT Authority", "USER");
                    break;
                case "S-1-5-80-0":
                    result = new MappedPrincipal("All Services ", "GROUP");
                    break;
                case "S-1-5-32-544":
                    result = new MappedPrincipal("Administrators", "GROUP");
                    break;
                case "S-1-5-32-545":
                    result = new MappedPrincipal("Users", "GROUP");
                    break;
                case "S-1-5-32-546":
                    result = new MappedPrincipal("Guests", "GROUP");
                    break;
                case "S-1-5-32-547":
                    result = new MappedPrincipal("Power Users", "GROUP");
                    break;
                case "S-1-5-32-548":
                    result = new MappedPrincipal("Account Operators", "GROUP");
                    break;
                case "S-1-5-32-549":
                    result = new MappedPrincipal("Server Operators", "GROUP");
                    break;
                case "S-1-5-32-550":
                    result = new MappedPrincipal("Print Operators", "GROUP");
                    break;
                case "S-1-5-32-551":
                    result = new MappedPrincipal("Backup Operators", "GROUP");
                    break;
                case "S-1-5-32-552":
                    result = new MappedPrincipal("Replicators", "GROUP");
                    break;
                case "S-1-5-32-554":
                    result = new MappedPrincipal("Pre-Windows 2000 Compatible Access", "GROUP");
                    break;
                case "S-1-5-32-555":
                    result = new MappedPrincipal("Remote Desktop Users", "GROUP");
                    break;
                case "S-1-5-32-556":
                    result = new MappedPrincipal("Network Configuration Operators", "GROUP");
                    break;
                case "S-1-5-32-557":
                    result = new MappedPrincipal("Incoming Forest Trust Builders", "GROUP");
                    break;
                case "S-1-5-32-558":
                    result = new MappedPrincipal("Performance Monitor Users", "GROUP");
                    break;
                case "S-1-5-32-559":
                    result = new MappedPrincipal("Performance Log Users", "GROUP");
                    break;
                case "S-1-5-32-560":
                    result = new MappedPrincipal("Windows Authorization Access Group", "GROUP");
                    break;
                case "S-1-5-32-561":
                    result = new MappedPrincipal("Terminal Server License Servers", "GROUP");
                    break;
                case "S-1-5-32-562":
                    result = new MappedPrincipal("Distributed COM Users", "GROUP");
                    break;
                case "S-1-5-32-568":
                    result = new MappedPrincipal("IIS_IUSRS", "GROUP");
                    break;
                case "S-1-5-32-569":
                    result = new MappedPrincipal("Cryptographic Operators", "GROUP");
                    break;
                case "S-1-5-32-573":
                    result = new MappedPrincipal("Event Log Readers", "GROUP");
                    break;
                case "S-1-5-32-574":
                    result = new MappedPrincipal("Certificate Service DCOM Access", "GROUP");
                    break;
                case "S-1-5-32-575":
                    result = new MappedPrincipal("RDS Remote Access Servers", "GROUP");
                    break;
                case "S-1-5-32-576":
                    result = new MappedPrincipal("RDS Endpoint Servers", "GROUP");
                    break;
                case "S-1-5-32-577":
                    result = new MappedPrincipal("RDS Management Servers", "GROUP");
                    break;
                case "S-1-5-32-578":
                    result = new MappedPrincipal("Hyper-V Administrators", "GROUP");
                    break;
                case "S-1-5-32-579":
                    result = new MappedPrincipal("Access Control Assistance Operators", "GROUP");
                    break;
                case "S-1-5-32-580":
                    result = new MappedPrincipal("Remote Management Users", "GROUP");
                    break;
                default:
                    result = null;
                    break;
            }
            return result != null;
        }
    }
}
