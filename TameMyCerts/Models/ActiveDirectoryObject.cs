// Copyright 2021 Uwe Gradenegger <uwe@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Principal;
using TameMyCerts.Enums;

namespace TameMyCerts.Models
{
    internal class ActiveDirectoryObject
    {
        private const StringComparison COMPARISON = StringComparison.InvariantCultureIgnoreCase;

        public ActiveDirectoryObject(string forestRootDomain, string dsAttribute, string identity,
            string objectCategory, string searchRoot)
        {
            if (!DsMappingAttributes.Any(s => s.Equals(dsAttribute, COMPARISON)))
            {
                throw new ArgumentException(string.Format(LocalizedStrings.DirVal_Invalid_Directory_Attribute,
                    dsAttribute));
            }

            if (!DsObjectTypes.Any(s => s.Equals(objectCategory, COMPARISON)))
            {
                throw new ArgumentException(string.Format(LocalizedStrings.DirVal_Invalid_Object_Category,
                    objectCategory));
            }

            var searchRootEntry = string.IsNullOrEmpty(searchRoot)
                ? new DirectoryEntry($"GC://{forestRootDomain}")
                : new DirectoryEntry($"LDAP://{searchRoot}");

            var directorySearcher = new DirectorySearcher(searchRoot)
            {
                SearchRoot = searchRootEntry,
                Filter = $"(&({dsAttribute}={identity})(objectCategory={objectCategory}))",
                PropertiesToLoad = {"memberOf", "userAccountControl", "objectSid"},
                PageSize = 2
            };

            foreach (var s in DsRetrievalAttributes)
            {
                directorySearcher.PropertiesToLoad.Add(s);
            }

            var searchResults = directorySearcher.FindAll();

            if (searchResults.Count < 1)
            {
                throw new ArgumentException(string.Format(LocalizedStrings.DirVal_Nothing_Found,
                    objectCategory, dsAttribute, identity, searchRootEntry.Path));
            }

            if (searchResults.Count > 1)
            {
                throw new ArgumentException(string.Format(LocalizedStrings.DirVal_Invalid_Result_Count,
                    objectCategory, dsAttribute, identity));
            }

            var dsObject = searchResults[0];

            UserAccountControl = (UserAccountControl) Convert.ToInt32(dsObject.Properties["userAccountControl"][0]);
            SecurityIdentifier = new SecurityIdentifier((byte[]) dsObject.Properties["objectSid"][0], 0);

            for (var index = 0; index < dsObject.Properties["memberOf"].Count; index++)
            {
                MemberOf.Add(dsObject.Properties["memberOf"][index].ToString());
            }

            foreach (var s in DsRetrievalAttributes.Where(s => dsObject.Properties[s].Count > 0))
            {
                Attributes.Add(s, (string) dsObject.Properties[s][0]);
            }

            Name = objectCategory.Equals("computer") ? Attributes["dNSHostName"] : Attributes["userPrincipalName"];
        }

        public ActiveDirectoryObject(string name, UserAccountControl userAccountControl, List<string> memberOf,
            Dictionary<string, string> attributes, SecurityIdentifier securityIdentifier)
        {
            Name = name;
            UserAccountControl = userAccountControl;
            MemberOf = memberOf;
            Attributes = attributes;
            SecurityIdentifier = securityIdentifier;
        }

        public string Name { get; }

        public UserAccountControl UserAccountControl { get; set; }

        public List<string> MemberOf { get; } = new List<string>();

        public Dictionary<string, string> Attributes { get; } = new Dictionary<string, string>();

        public SecurityIdentifier SecurityIdentifier { get; }

        private static IEnumerable<string> DsMappingAttributes { get; } = new List<string>
            {"cn", "name", "sAMAccountName", "userPrincipalName", "dNSHostName"};

        private static IEnumerable<string> DsObjectTypes { get; } = new List<string> {"computer", "user"};

        private static IEnumerable<string> DsRetrievalAttributes { get; } = new List<string>
        {
            "c", "co", "company", "department", "departmentNumber", "description", "displayName", "division",
            "dNSHostName", "employeeID", "employeeNumber", "employeeType", "extensionAttribute1",
            "extensionAttribute10", "extensionAttribute11", "extensionAttribute12", "extensionAttribute13",
            "extensionAttribute14", "extensionAttribute15", "extensionAttribute2", "extensionAttribute3",
            "extensionAttribute4", "extensionAttribute5", "extensionAttribute6", "extensionAttribute7",
            "extensionAttribute8", "extensionAttribute9", "facsimileTelephoneNumber", "gecos", "givenName", "homePhone",
            "homePostalAddress", "info", "initials", "l", "location", "mail", "mailNickname", "middleName", "mobile",
            "name", "otherMailbox", "otherMobile", "otherPager", "otherTelephone", "pager", "personalPager",
            "personalTitle", "postalAddress", "postalCode", "postOfficeBox", "sAMAccountName", "sn", "st", "street",
            "streetAddress", "telephoneNumber", "telexNumber", "title", "userPrincipalName"
        };
    }
}