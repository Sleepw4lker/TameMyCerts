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
    public class DirectoryServicesValidator
    {
        private static readonly StringComparison StringComparison = StringComparison.InvariantCultureIgnoreCase;

        private static readonly string[] DsMappingAttributes =
            {"cn", "name", "sAMAccountName", "userPrincipalName", "dNSHostName"};

        private static readonly string[] DsObjectTypes = {"computer", "user"};

        private static readonly string[] DsRetrievalAttributes =
        {
            "c", "l", "company", "displayName", "department", "givenName", "initials", "mail", "name", "sAMAccountName",
            "sn", "st", "streetAddress", "title", "userPrincipalName"
        };

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

        public DirectoryServicesValidator()
        {
            _forestRootDomain = GetForestRootDomain();
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
                return null;
            }
        }

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestPolicy certificateRequestPolicy,
            CertificateRequestValidationResult result)
        {
            var dsMapping = certificateRequestPolicy.DirectoryServicesMapping;

            if (!DsMappingAttributes.Any(s => s.Equals(dsMapping.DirectoryServicesAttribute, StringComparison)))
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.DirVal_Invalid_Directory_Attribute,
                    dsMapping.DirectoryServicesAttribute));
                return result;
            }

            if (!DsObjectTypes.Any(s => s.Equals(dsMapping.ObjectCategory, StringComparison)))
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.DirVal_Invalid_Object_Category,
                    dsMapping.ObjectCategory));
                return result;
            }

            var identity = result.Identities.FirstOrDefault(x => x.Key.Equals(dsMapping.CertificateAttribute)).Value;

            if (string.IsNullOrEmpty(identity))
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.DirVal_No_Cert_Identity, dsMapping.CertificateAttribute));
                return result;
            }

            var searchRoot = string.IsNullOrEmpty(dsMapping.SearchRoot)
                ? new DirectoryEntry($"GC://{_forestRootDomain}")
                : new DirectoryEntry($"LDAP://{dsMapping.SearchRoot}");

            var directorySearcher = new DirectorySearcher(searchRoot)
            {
                SearchRoot = searchRoot,
                Filter =
                    $"(&({dsMapping.DirectoryServicesAttribute}={identity})(objectCategory={dsMapping.ObjectCategory}))",
                PropertiesToLoad = {"memberOf", "userAccountControl", "objectSid"},
                PageSize = 2
            };

            // Load additional properties required for building the Subject DN
            if (dsMapping.SubjectDistinguishedName.Count > 0)
            {
                foreach (var s in DsRetrievalAttributes)
                {
                    directorySearcher.PropertiesToLoad.Add(s);
                }
            }

            SearchResultCollection searchResults;
            try
            {
                searchResults = directorySearcher.FindAll();
            }
            catch (Exception ex)
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.DirVal_Query_Failed, ex.Message));
                return result;
            }

            if (searchResults.Count < 1)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.DirVal_Nothing_Found, dsMapping.ObjectCategory,
                        dsMapping.DirectoryServicesAttribute, identity, searchRoot.Path));
                return result;
            }

            if (searchResults.Count > 1)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.DirVal_Invalid_Result_Count, dsMapping.ObjectCategory,
                        dsMapping.DirectoryServicesAttribute, identity));
                return result;
            }

            var dsObject = searchResults[0];

            if ((Convert.ToInt32(dsObject.Properties["userAccountControl"][0]) & UserAccountControl.ACCOUNTDISABLE) ==
                UserAccountControl.ACCOUNTDISABLE)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.DirVal_Account_Disabled, dsMapping.ObjectCategory, identity));
                return result;
            }

            #region process memberships of allowed groups

            if (dsMapping.AllowedSecurityGroups.Count > 0)
            {
                var matchFound = false;
                for (var index = 0; index < dsObject.Properties["memberOf"].Count; index++)
                {
                    var group = dsObject.Properties["memberOf"][index];
                    if (dsMapping.AllowedSecurityGroups.Any(s => s.Equals(group.ToString(), StringComparison)))
                    {
                        matchFound = true;
                    }
                }

                if (!matchFound)
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                        LocalizedStrings.DirVal_Account_Groups_Not_Allowed,
                        dsMapping.ObjectCategory, identity));
                }
            }

            #endregion

            #region process memberships of disallowed groups

            if (dsMapping.DisallowedSecurityGroups.Count > 0)
            {
                for (var index = 0; index < dsObject.Properties["memberOf"].Count; index++)
                {
                    var group = dsObject.Properties["memberOf"][index];
                    if (dsMapping.DisallowedSecurityGroups.Any(s => s.Equals(group.ToString(), StringComparison)))
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                            LocalizedStrings.DirVal_Account_Groups_Disallowed,
                            dsMapping.ObjectCategory, identity, group));
                    }
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

                if (!DsRetrievalAttributes.Any(s => s.Equals(rdn.DirectoryServicesAttribute, StringComparison)))
                {
                    if (rdn.Mandatory)
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                            string.Format(LocalizedStrings.DirVal_Rdn_Invalid_Directory_Attribute,
                                rdn.DirectoryServicesAttribute, rdn.Field));
                    }

                    continue;
                }

                if (dsObject.Properties[rdn.DirectoryServicesAttribute].Count == 0)
                {
                    if (rdn.Mandatory)
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                            string.Format(LocalizedStrings.DirVal_Rdn_Empty_Directory_Attribute,
                                rdn.DirectoryServicesAttribute, rdn.Field));
                    }

                    continue;
                }

                var dsAttribute = (string) dsObject.Properties[rdn.DirectoryServicesAttribute][0];

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

                result.Properties.Add(new KeyValuePair<string, string>(RdnInfo[rdn.Field].NameProperty, dsAttribute));
            }

            #endregion

            #region Process SID certificate extension construction

            if (certificateRequestPolicy.SecurityIdentifierExtension.Equals("Add", StringComparison))
            {
                var objectSid = new SecurityIdentifier((byte[]) dsObject.Properties["objectSid"][0], 0).ToString();
                result.Extensions.Add(new KeyValuePair<string, string>(WinCrypt.szOID_DS_CA_SECURITY_EXT,
                    new SidCertificateExtension(objectSid).Value));
            }

            #endregion

            return result;
        }
    }
}