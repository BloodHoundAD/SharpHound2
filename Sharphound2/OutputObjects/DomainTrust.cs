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

        public override string ToString()
        {
            return $"{nameof(SourceDomain)}: {SourceDomain}, {nameof(TargetDomain)}: {TargetDomain}, {nameof(TrustDirection)}: {TrustDirection}, {nameof(TrustType)}: {TrustType}, {nameof(IsTransitive)}: {IsTransitive}";
        }

        public override string ToCsv()
        {
            return $"{SourceDomain},{TargetDomain},{TrustDirection},{TrustType},{IsTransitive}";
        }

        public override object ToParam()
        {
            throw new NotImplementedException();
        }

        public override string TypeHash()
        {
            return "domain|Trust|domain";
        }

        internal IEnumerable<object> ToMultipleParam()
        {
            switch (TrustDirection)
            {
                case "Inbound":
                    yield return new
                    {
                        a = TargetDomain,
                        b = SourceDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive
                    };
                    break;
                case "Outbound":
                    yield return new
                    {
                        a = SourceDomain,
                        b = TargetDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive
                    };
                    break;
                default:
                    yield return new
                    {
                        a = SourceDomain,
                        b = TargetDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive
                    };
                    yield return new
                    {
                        a = TargetDomain,
                        b = SourceDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive
                    };
                    break;
            }
        }
    }
}
