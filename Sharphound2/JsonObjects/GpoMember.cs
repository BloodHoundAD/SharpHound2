namespace Sharphound2.JsonObjects
{
    internal class GpoMember : JsonBase
    {
        public string[] AffectedComputers { get; set; }
        public LocalMember[] RemoteDesktopUsers { get; set; }
        public LocalMember[] LocalAdmins { get; set; }
        public LocalMember[] DcomUsers { get; set; }
    }
}
