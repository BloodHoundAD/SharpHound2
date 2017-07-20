using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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
        Cache,
        SessionLoop,
        Default
    }
}
