using System.Collections.Generic;

namespace Sharphound2.OutputObjects
{
    internal class RestOutput
    {
        public List<object> Props;
        private readonly Query _query;

        internal RestOutput(Query type)
        {
            Props = new List<object>();
            _query = type;
        }

        internal object GetStatement()
        {
            return new
            {
                statement = _query.Value,
                parameters = new
                {
                    props = Props.ToArray()
                }
            };
        }

        internal void Reset()
        {
            Props = new List<object>();
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }

    internal class RestCollection
    {
        
    }

    internal class RestOutputAcl
    {
        public List<object> Props;

        internal RestOutputAcl()
        {
            Props = new List<object>();
        }

        internal string CreateStatement(string q)
        {
            var s = q.Split('|');
            return $"UNWIND {{props}} AS prop MERGE (a:{s[0].ToTitleCase()} {{name:prop.account}}) WITH a,prop MERGE (b:{s[2].ToTitleCase()} {{name: prop.principal}}) WITH a,b,prop MERGE (a)-[r:{s[1]} {{isACL:true}}]->(b)";
        }

        internal object GetStatement(string queryType)
        {
            return new
            {
                statement = CreateStatement(queryType),
                parameters = new
                {
                    props = Props.ToArray()
                }
            };
        }
    }

    internal class Query
    {
        internal string Value { get; set; }
        
        internal Query(string value) { Value = value; }

        public static Query LocalAdminUser => new Query("UNWIND {props} AS prop MERGE (user:User {name: prop.account}) WITH user,prop MERGE (computer:Computer {name: prop.computer}) WITH user,computer MERGE (user)-[:AdminTo]->(computer)");
        public static Query LocalAdminGroup => new Query("UNWIND {props} AS prop MERGE (group:Group {name: prop.account}) WITH group,prop MERGE (computer:Computer {name: prop.computer}) WITH group,computer MERGE (group)-[:AdminTo]->(computer)");
        public static Query LocalAdminComputer => new Query("UNWIND {props} AS prop MERGE (computer1:Computer {name: prop.account}) WITH computer1,prop MERGE (computer2:Computer {name: prop.computer}) WITH computer1,computer2 MERGE (computer1)-[:AdminTo]->(computer2)");

        public static Query Sessions => new Query("UNWIND {props} AS prop MERGE (user:User {name:prop.account}) WITH user,prop MERGE (computer:Computer {name: prop.computer}) WITH user,computer,prop MERGE (computer)-[:HasSession {Weight : prop.weight}]-(user)");

        public static Query GroupMembershipUser => new Query("UNWIND {props} AS prop MERGE (user:User {name:prop.account}) WITH user,prop MERGE (group:Group {name:prop.group}) WITH user,group MERGE (user)-[:MemberOf]->(group)");
        public static Query GroupMembershipGroup => new Query("UNWIND {props} AS prop MERGE (group1:Group {name:prop.account}) WITH group1,prop MERGE (group2:Group {name:prop.group}) WITH group1,group2 MERGE (group1)-[:MemberOf]->(group2)");
        public static Query GroupMembershipComputer => new Query("UNWIND {props} AS prop MERGE (computer:Computer {name:prop.account}) WITH computer,prop MERGE (group:Group {name:prop.group}) WITH computer,group MERGE (computer)-[:MemberOf]->(group)");

        public static Query Domain => new Query("UNWIND {props} AS prop MERGE (domain1:Domain {name: prop.domain1}) WITH domain1,prop MERGE (domain2:Domain {name: prop.domain2}) WITH domain1,domain2,prop MERGE (domain1)-[:TrustedBy {TrustType : prop.trusttype, Transitive: prop.transitive}]->(domain2)");
    }

    internal enum QueryType
    {
        LocalAdminUser,
        LocalAdminGroup,
        LocalAdminComputer,
        Session,
        GroupMembershipUser,
        GroupMembershipComputer,
        GroupMembershipGroup,
        DomainTrust
    }
}
