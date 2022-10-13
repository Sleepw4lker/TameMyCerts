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

namespace TameMyCerts
{
    public class ActiveDirectoryObject
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

            Name = identity;

            var searchRootEntry = string.IsNullOrEmpty(searchRoot)
                ? new DirectoryEntry($"GC://{forestRootDomain}")
                : new DirectoryEntry($"LDAP://{searchRoot}");

            var directorySearcher = new DirectorySearcher(searchRoot)
            {
                SearchRoot = searchRootEntry,
                Filter =
                    $"(&({dsAttribute}={identity})(objectCategory={objectCategory}))",
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
                throw new ArgumentException(string.Format(LocalizedStrings.DirVal_Nothing_Found, objectCategory,
                    dsAttribute, identity, searchRootEntry.Path));
            }

            if (searchResults.Count > 1)
            {
                throw new ArgumentException(string.Format(LocalizedStrings.DirVal_Invalid_Result_Count, objectCategory,
                    dsAttribute, identity));
            }

            var dsObject = searchResults[0];

            UserAccountControl = Convert.ToInt32(dsObject.Properties["userAccountControl"][0]);
            SecurityIdentifier = new SecurityIdentifier((byte[]) dsObject.Properties["objectSid"][0], 0);

            for (var index = 0; index < dsObject.Properties["memberOf"].Count; index++)
            {
                MemberOf.Add(dsObject.Properties["memberOf"][index].ToString());
            }

            foreach (var s in DsRetrievalAttributes)
            {
                if (dsObject.Properties[s].Count > 0)
                {
                    Attributes.Add(s, (string) dsObject.Properties[s][0]);
                }
            }
        }

        public ActiveDirectoryObject(string name, int userAccountControl, List<string> memberOf,
            Dictionary<string, string> attributes, SecurityIdentifier securityIdentifier)
        {
            Name = name;
            UserAccountControl = userAccountControl;
            MemberOf = memberOf;
            Attributes = attributes;
            SecurityIdentifier = securityIdentifier;
        }

        public string Name { get; }

        public int UserAccountControl { get; set; }

        public List<string> MemberOf { get; } = new List<string>();

        public Dictionary<string, string> Attributes { get; } = new Dictionary<string, string>();

        public SecurityIdentifier SecurityIdentifier { get; }

        private static string[] DsMappingAttributes { get; } =
            {"cn", "name", "sAMAccountName", "userPrincipalName", "dNSHostName"};

        private static string[] DsObjectTypes { get; } = {"computer", "user"};

        private static string[] DsRetrievalAttributes { get; } =
        {
            "c", "l", "company", "displayName", "department", "givenName", "initials", "mail", "name", "sAMAccountName",
            "sn", "st", "streetAddress", "title", "userPrincipalName"
        };
    }

    public class DirectoryServicesValidator
    {
        private const StringComparison COMPARISON = StringComparison.InvariantCultureIgnoreCase;

        private static readonly Dictionary<string, (string NameProperty, int MaxLength)> RdnInfo =
            new Dictionary<string, (string NameProperty, int MaxLength)>
            {
                {"emailAddress", ("Subject.Email", 128)},
                {"commonName", ("Subject.CommonName", 64)},
                {"organizationName", ("Subject.Organization", 64)},
                {"organizationalUnitName", ("Subject.OrgUnit", 64)},
                {"localityName", ("Subject.Locality", 128)},
                {"stateOrProvinceName", ("Subject.State", 128)},
                {"countryName", ("Subject.Country", 2)},
                {"title", ("Subject.Title", 64)},
                {"givenName", ("Subject.GivenName", 16)},
                {"initials", ("Subject.Initials", 5)},
                {"surname", ("Subject.SurName", 40)},
                {"streetAddress", ("Subject.StreetAddress", 30)}
            };

        private readonly string _forestRootDomain;

        public DirectoryServicesValidator(bool forTesting = false)
        {
            if (!forTesting)
            {
                _forestRootDomain = GetForestRootDomain();
            }
        }

        private static string GetForestRootDomain()
        {
            try
            {
                var directoryEntry = new DirectoryEntry("LDAP://RootDSE");
                return directoryEntry.Properties["rootDomainNamingContext"][0].ToString();
            }
            catch
            {
                // TODO: Maybe we should throw an exception here
                return null;
            }
        }

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestPolicy certificateRequestPolicy,
            CertificateRequestValidationResult result)
        {
            var dsMapping = certificateRequestPolicy.DirectoryServicesMapping;

            var identity = result.Identities.FirstOrDefault(x => x.Key.Equals(dsMapping.CertificateAttribute)).Value;

            if (string.IsNullOrEmpty(identity))
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.DirVal_No_Cert_Identity, dsMapping.CertificateAttribute));
                return result;
            }

            try
            {
                var dsObject = new ActiveDirectoryObject(_forestRootDomain, dsMapping.DirectoryServicesAttribute,
                    identity, dsMapping.ObjectCategory, dsMapping.SearchRoot);

                return VerifyRequest(certificateRequestPolicy, result, dsObject);
            }
            catch (Exception ex)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, ex.Message);
                return result;
            }
        }

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestPolicy certificateRequestPolicy,
            CertificateRequestValidationResult result, ActiveDirectoryObject dsObject)
        {
            var dsMapping = certificateRequestPolicy.DirectoryServicesMapping;

            #region Process enablement status of the account

            if ((dsObject.UserAccountControl & UserAccountControl.ACCOUNTDISABLE) ==
                UserAccountControl.ACCOUNTDISABLE && !dsMapping.PermitDisabledAccounts)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.DirVal_Account_Disabled, dsMapping.ObjectCategory, dsObject.Name));
                return result;
            }

            #endregion

            #region process memberships of allowed groups

            if (dsMapping.AllowedSecurityGroups.Count > 0)
            {
                var matches = dsObject.MemberOf.Count(group =>
                    dsMapping.AllowedSecurityGroups.Any(s => s.Equals(group, COMPARISON)));

                if (matches == 0)
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                        LocalizedStrings.DirVal_Account_Groups_Not_Allowed,
                        dsMapping.ObjectCategory, dsObject.Name));
                }
            }

            #endregion

            #region process memberships of disallowed groups

            if (dsMapping.DisallowedSecurityGroups.Count > 0)
            {
                foreach (var group in dsObject.MemberOf.Where(group =>
                             dsMapping.DisallowedSecurityGroups.Any(s => s.Equals(group, COMPARISON))))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                        LocalizedStrings.DirVal_Account_Groups_Disallowed,
                        dsMapping.ObjectCategory, dsObject.Name, group));
                }
            }

            #endregion

            #region Process addition of Subject Relative Distinguished Names

            foreach (var rdn in dsMapping.SubjectDistinguishedName)
            {
                if (!RdnInfo.ContainsKey(rdn.Field))
                {
                    if (rdn.Mandatory)
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                            string.Format(LocalizedStrings.DirVal_Rdn_Invalid_Field, rdn.Field));
                    }

                    continue;
                }

                if (!dsObject.Attributes.ContainsKey(rdn.DirectoryServicesAttribute))
                {
                    if (rdn.Mandatory)
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                            string.Format(LocalizedStrings.DirVal_Rdn_Invalid_Directory_Attribute,
                                rdn.DirectoryServicesAttribute, rdn.Field));
                    }

                    continue;
                }

                var dsAttribute = dsObject.Attributes[rdn.DirectoryServicesAttribute];

                if (dsAttribute.Length > RdnInfo[rdn.Field].MaxLength)
                {
                    if (rdn.Mandatory)
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                            string.Format(LocalizedStrings.DirVal_Rdn_Directory_Attribute_too_long, dsAttribute,
                                rdn.DirectoryServicesAttribute, rdn.Field, RdnInfo[rdn.Field].NameProperty,
                                dsAttribute.Length));
                    }

                    continue;
                }

                result.Properties.Add(RdnInfo[rdn.Field].NameProperty, dsAttribute);
            }

            #endregion

            #region Process SID certificate extension construction

            if (certificateRequestPolicy.SecurityIdentifierExtension.Equals("Add", COMPARISON))
            {
                var objectSid = dsObject.SecurityIdentifier.ToString();
                result.Extensions.Add(WinCrypt.szOID_DS_CA_SECURITY_EXT, new SidCertificateExtension(objectSid).Value);
            }

            #endregion

            return result;
        }
    }
}