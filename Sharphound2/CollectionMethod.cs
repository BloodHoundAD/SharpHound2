using System;

namespace Sharphound2
{
    public enum CollectionMethod
    {
        Group,
        ComputerOnly,
        LocalGroup,
        GPOLocalGroup,
        Session,
        LoggedOn,
        Trusts,
        ACL,
        SessionLoop,
        Default,
        ObjectProps,
        Container,
        RDP,
        DCOM,
        DcOnly,
        All
    }

    [Flags]
    public enum ResolvedCollectionMethod
    {
        None = 0,
        Group = 1,
        LocalGroup = 1 << 1,
        GPOLocalGroup = 1 << 2,
        Session = 1 << 3,
        LoggedOn = 1 << 4,
        Trusts = 1 << 5,
        ACL = 1 << 6,
        Container = 1 << 7,
        RDP = 1 << 8,
        ObjectProps = 1 << 9,
        SessionLoop = 1 << 10,
        LoggedOnLoop = 1 << 11,
        DCOM = 1 << 12,
    }
}
