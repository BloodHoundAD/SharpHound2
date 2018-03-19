using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Sharphound2
{
    internal enum FileTypes
    {
        [Description("GroupName,AccountName,AccountType")]
        GroupMembership,
        [Description("ComputerName,AccountName,AccountType")]
        LocalAdmin,
        [Description("UserName,ComputerName,Weight")]
        Session,
        [Description("AccountName,DisplayName,Enabled,PwdLastSet,LastLogon,Sid,SidHistory,HasSPN,ServicePrincipalNames,Email,Domain")]
        UserProperties,
        [Description("SourceDomain,TargetDomain,TrustDirection,TrustType,Transitive")]
        Trusts,
        [Description("AccountName,Enabled,UnconstrainedDelegation,PwdLastSet,LastLogon,OperatingSystem,Sid,Domain")]
        ComputerProperties,
        [Description("ObjectName,ObjectType,PrincipalName,PrincipalType,ActiveDirectoryRights,ACEType,AccessControlType,IsInherited,ObjectGuid")]
        Acl,
        [Description("ObjectType,ObjectName,ObjectGUID,GPODisplayName,GPOGuid,IsEnforced")]
        GpLink,
        [Description("ContainerType,ContainerName,ContainerGUID,ContainerBlocksInheritance,ObjectType,ObjectName,ObjectId")]
        Containers
    }

    internal class CsvContainer
    {
        internal string FileName { get; set; }
        internal FileTypes FileType { get; set; }

        public static string GetFileTypeHeader(FileTypes value)
        {
            var fi = value.GetType().GetField(value.ToString());

            var attributes =
                (DescriptionAttribute[])fi.GetCustomAttributes(typeof(DescriptionAttribute), false);

            return attributes.Length > 0 ? attributes[0].Description : value.ToString();
        }
    }
}
