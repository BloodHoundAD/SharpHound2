using System;
using System.Collections.Generic;

namespace Sharphound2.OutputObjects
{
    internal class DomainTrust : OutputBase
    {
        public string SourceDomain { get; set; }
        public string TargetDomain { get; set; }
        public string TrustDirection { get; set; }
        public string TrustType { get; set; }
        public bool IsTransitive { get; set; }

        public override string ToCsv()
        {
            return $"{SourceDomain},{TargetDomain},{TrustDirection},{TrustType},{IsTransitive}";
        }

        public override object ToParam()
        {
            throw new NotImplementedException();
        }

        internal List<object> ToMultipleParam()
        {
            var r = new List<object>();
            switch (TrustDirection)
            {
                case "Inbound":
                    r.Add(new
                    {
                        domain1 = TargetDomain,
                        domain2 = SourceDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive
                    });
                    break;
                case "Outbound":
                    r.Add(new
                    {
                        domain1 = SourceDomain,
                        domain2 = TargetDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive
                    });
                    break;
                default:
                    r.Add(new
                    {
                        domain1 = SourceDomain,
                        domain2 = TargetDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive
                    });
                    r.Add(new
                    {
                        domain1 = TargetDomain,
                        domain2 = SourceDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive
                    });
                    break;
            }

            return r;
        }
    }
}
