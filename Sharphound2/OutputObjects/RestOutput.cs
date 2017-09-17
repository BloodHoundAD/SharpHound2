using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Web.Script.Serialization;

namespace Sharphound2.OutputObjects
{
    internal class RestOutput
    {
        private Dictionary<string, List<object>> _collection;

        internal RestOutput()
        {
            _collection = new Dictionary<string, List<object>>();
        }

        internal object GetStatements()
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
                        $"UNWIND {{props}} AS prop MERGE (a:{atype} {{name:prop.a}}) WITH a,prop MERGE (b:{btype} {{name:prop.b}}) WITH a,b,prop MERGE (a)-[:{reltype} {{Weight:prop.weight}}]->(b)";
                }else if (reltype.Equals("Trust"))
                {
                    statement =
                        $"UNWIND {{props}} AS prop MERGE (a:{atype} {{name:prop.a}}) WITH a,prop MERGE (b:{btype} {{name:prop.b}}) WITH a,b,prop MERGE (a)-[:{reltype} {{TrustType: prop.trusttype, Transitive: prop.transitive}}]->(b)";
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
            return new
            {
                statements = statements
            };
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
}
