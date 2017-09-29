using System.Collections.Generic;
using System.Linq;

namespace Sharphound2.OutputObjects
{
    internal class RestOutput
    {
        private Dictionary<string, List<object>> _collection;

        private readonly HashSet<string> _aclTypes = new HashSet<string> {
            "DCSync", "AllExtendedRights", "ForceChangePassword", "GenericAll", "GenericWrite", "WriteDACL",
            "WriteOwner", "AddMembers"
        };

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
                        $"UNWIND {{props}} AS prop MERGE (a:{atype.ToTitleCase()} {{name:prop.a}}) WITH a,prop MERGE (b:{btype.ToTitleCase()} {{name:prop.b}}) WITH a,b,prop MERGE (a)-[:{reltype} {{Weight:prop.weight, isACL: false}}]->(b)";
                }else if (reltype.Equals("CompProp"))
                {
                    statement =
                        $"UNWIND {{props}} AS prop MERGE (a:Computer {{name:upper(prop.ComputerName)}}) SET a.Enabled=toBoolean(prop.Enabled),a.UnconstrainedDelegation=toBoolean(prop.UnconstrainedDelegation),a.PwdLastSet=toInt(prop.PwdLastSet),a.LastLogon=toInt(prop.LastLogon),a.OperatingSystem=prop.OperatingSystem,a.Sid=prop.ObjectSid";
                }else if (reltype.Equals("UserProp"))
                {
                    statement =
                        $"UNWIND {{props}} AS prop MERGE (a:User {{name:upper(prop.AccountName)}}) SET a.DisplayName=prop.DisplayName,a.Enabled=toBoolean(prop.Enabled),a.PwdLastSet=toInt(prop.PwdLastSet),a.LastLogon=toInt(prop.LastLogon),a.ObjectSid=prop.ObjectSid,a.SidHistory=prop.SidHistory,a.HasSPN=toBoolean(prop.HasSpn),a.ServicePrincipalNames=split(prop.ServicePrincipalNames,'|')";
                }
                else if (reltype.Equals("Trust"))
                {
                    statement =
                        $"UNWIND {{props}} AS prop MERGE (a:{atype.ToTitleCase()} {{name:prop.a}}) WITH a,prop MERGE (b:{btype.ToTitleCase()} {{name:prop.b}}) WITH a,b,prop MERGE (a)-[:{reltype} {{TrustType: prop.trusttype, Transitive: prop.transitive, isACL: false}}]->(b)";
                }else if (_aclTypes.Contains(reltype))
                {
                    statement =
                        $"UNWIND {{props}} AS prop MERGE (a:{atype.ToTitleCase()} {{name:prop.a}}) WITH a,prop MERGE (b:{btype.ToTitleCase()} {{name:prop.b}}) WITH a,b MERGE (a)-[:{reltype} {{isACL: true}}]->(b)";
                }
                else
                {
                    statement =
                        $"UNWIND {{props}} AS prop MERGE (a:{atype.ToTitleCase()} {{name:prop.a}}) WITH a,prop MERGE (b:{btype.ToTitleCase()} {{name:prop.b}}) WITH a,b MERGE (a)-[:{reltype} {{isACL: false}}]->(b)";
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
