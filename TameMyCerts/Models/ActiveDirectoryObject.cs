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
            string objectCategory, string searchRoot, bool loadExtendedAttributes = false)
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

            // Automatically determine the searchRoot from the global catalog
            if (string.IsNullOrEmpty(searchRoot))
            {
                var searchResult = GetDirectoryEntry($"GC://{forestRootDomain}", dsAttribute, identity, objectCategory,
                    new List<string> {"distinguishedName"});
                searchRoot = (string) searchResult.Properties["distinguishedName"][0];
            }

            var attributesToRetrieve = new List<string>
                {"memberOf", "userAccountControl", "objectSid", "distinguishedName"};

            // Only load extended attributes if we have a use for them (e.g. modifying Subject DN from AD attributes)
            attributesToRetrieve.AddRange(loadExtendedAttributes
                ? DsRetrievalAttributes
                : new List<string> {"sAMAccountName"}); // "sAMAccountName" attribute is mandatory

            var dsObject = GetDirectoryEntry($"LDAP://{searchRoot}", dsAttribute, identity, objectCategory,
                attributesToRetrieve);

            UserAccountControl = (UserAccountControl) Convert.ToInt32(dsObject.Properties["userAccountControl"][0]);
            SecurityIdentifier = new SecurityIdentifier((byte[]) dsObject.Properties["objectSid"][0], 0);
            DistinguishedName = (string) dsObject.Properties["distinguishedName"][0]; // userPrincipalName is not guaranteed to be populated

            for (var index = 0; index < dsObject.Properties["memberOf"].Count; index++)
            {
                MemberOf.Add(dsObject.Properties["memberOf"][index].ToString());
            }

            foreach (var s in DsRetrievalAttributes.Where(s => dsObject.Properties[s].Count > 0))
            {
                Attributes.Add(s, (string) dsObject.Properties[s][0]);
            }
        }

        public ActiveDirectoryObject(string distinguishedName, UserAccountControl userAccountControl, List<string> memberOf,
            Dictionary<string, string> attributes, SecurityIdentifier securityIdentifier)
        {
            DistinguishedName = distinguishedName;
            UserAccountControl = userAccountControl;
            MemberOf = memberOf;
            Attributes = attributes;
            SecurityIdentifier = securityIdentifier;
        }

        public string DistinguishedName { get; }

        public UserAccountControl UserAccountControl { get; set; }

        public List<string> MemberOf { get; } = new List<string>();

        public Dictionary<string, string> Attributes { get; } =
            new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

        public SecurityIdentifier SecurityIdentifier { get; }

        private static IEnumerable<string> DsMappingAttributes { get; } = new List<string>
            {"cn", "name", "sAMAccountName", "userPrincipalName", "dNSHostName"};

        private static IEnumerable<string> DsObjectTypes { get; } = new List<string> {"computer", "user"};

        private static List<string> DsRetrievalAttributes { get; } = new List<string>
        {
            "c", "co", "cn", "company", "department", "departmentNumber", "description", "displayName", "division",
            "dNSHostName", "employeeID", "employeeNumber", "employeeType", "extensionAttribute1",
            "extensionAttribute10", "extensionAttribute11", "extensionAttribute12", "extensionAttribute13",
            "extensionAttribute14", "extensionAttribute15", "extensionAttribute2", "extensionAttribute3",
            "extensionAttribute4", "extensionAttribute5", "extensionAttribute6", "extensionAttribute7",
            "extensionAttribute8", "extensionAttribute9", "facsimileTelephoneNumber", "gecos", "givenName", "homePhone",
            "homePostalAddress", "info", "initials", "l", "location", "mail", "mailNickname", "middleName", "mobile",
            "name", "otherMailbox", "otherMobile", "otherPager", "otherTelephone", "pager", "personalPager",
            "personalTitle", "postalAddress", "postalCode", "postOfficeBox", "sAMAccountName", "sn", "st", "street",
            "streetAddress", "telephoneNumber", "title", "userPrincipalName"
        };

        private static SearchResult GetDirectoryEntry(string searchRoot, string dsAttribute, string identity,
            string objectCategory, List<string> searchProperties)
        {
            var searchRootEntry = new DirectoryEntry(searchRoot);

            var directorySearcher = new DirectorySearcher
            {
                SearchRoot = searchRootEntry,
                Filter = $"(&({dsAttribute}={identity})(objectCategory={objectCategory}))",
                PageSize = 2,
                ClientTimeout = new TimeSpan(0, 0, 15)
            };

            foreach (var s in searchProperties)
            {
                directorySearcher.PropertiesToLoad.Add(s);
            }

            SearchResultCollection searchResults;
            try
            {
                searchResults = directorySearcher.FindAll();
            }
            catch (Exception ex)
            {
                throw new ArgumentException(string.Format(LocalizedStrings.DirVal_Query_Failed, ex.Message));
            }

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

            return searchResults[0];
        }
    }
}