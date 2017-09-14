using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Web.Script.Serialization;

namespace Sharphound2.OutputObjects
{
    internal class RestOutput
    {
        private readonly Query _query;
        private Dictionary<string, List<object>> _collection;

        internal RestOutput()
        {
            _collection = new Dictionary<string, List<object>>();
        }

        internal void GetStatements()
        {
            var tempStatements = new List<object>();
            foreach (var key in _collection.Keys)
            {
                var split = key.Split('|');
                var atype = split[0];
                var reltype = split[1];
                var btype = split[2];

                string statement;
                if (reltype.Equals("HasSession"))
                {
                    statement =
                        $"UNWIND {{props}} AS prop MERGE (a:{atype} {{name:prop.a}}) WITH a,prop MERGE (b:{btype} {{name:prop.b}}) WITH a,b MERGE (a)-[:{reltype} {{Weight:prop.weight}}]->(b)";
                }else if (reltype.Equals("Trust"))
                {
                    statement =
                        $"UNWIND {{props}} AS prop MERGE (a:{atype} {{name:prop.a}}) WITH a,prop MERGE (b:{btype} {{name:prop.b}}) WITH a,b MERGE (a)-[:{reltype} {{TrustType: prop.trusttype, Transitive: prop.transitive}}]->(b)";
                }
                else
                {
                    statement =
                        $"UNWIND {{props}} AS prop MERGE (a:{atype} {{name:prop.a}}) WITH a,prop MERGE (b:{btype} {{name:prop.b}}) WITH a,b MERGE (a)-[:{reltype}]->(b)";
                }
                
                tempStatements.Add(new
                {
                    statement,
                    parameters = new
                    {
                        props = _collection[key].ToArray()
                    }
                });
            }

            var statements = new object[tempStatements.Count];

            for (var i = 0; i < tempStatements.Count; i++)
            {
                statements[i] = tempStatements[i];
            }
            var serializer = new JavaScriptSerializer();
            Console.WriteLine(serializer.Serialize(statements));
        }

        internal void AddNewData(string hash, object data)
        {
            if (_collection.ContainsKey(hash))
            {
                _collection[hash].Add(data);
            }
            else
            {
                _collection.Add(hash, new List<object> {data});
            }
        }

        internal void Reset()
        {
            _collection = new Dictionary<string, List<object>>();
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
