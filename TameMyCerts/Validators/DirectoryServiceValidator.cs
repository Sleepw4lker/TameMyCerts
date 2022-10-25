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
using TameMyCerts.Enums;
using TameMyCerts.Models;

namespace TameMyCerts.Validators
{
    internal class DirectoryServiceValidator
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
                {"streetAddress", ("Subject.StreetAddress", 30)},
                {"unstructuredName", ("Subject.UnstructuredName", 1024)},
                {"unstructuredAddress", ("Subject.UnstructuredAddress", 1024)},
                {"serialNumber", ("Subject.DeviceSerialNumber", 1024)}
            };

        private readonly string _forestRootDomain;

        public DirectoryServiceValidator(bool forTesting = false)
        {
            if (!forTesting)
            {
                _forestRootDomain = GetForestRootDomain();
            }
        }

        private static string GetForestRootDomain()
        {
            var directoryEntry = new DirectoryEntry("LDAP://RootDSE");
            return directoryEntry.Properties["rootDomainNamingContext"][0].ToString();
        }

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
            CertificateRequestPolicy requestPolicy, CertificateTemplateInfo.Template templateInfo)
        {
            var dsMapping = requestPolicy.DirectoryServicesMapping;

            var certificateAttribute = dsMapping.CertificateAttribute;
            var dsAttribute = dsMapping.DirectoryServicesAttribute;
            var objectCategory = dsMapping.ObjectCategory;

            if (!templateInfo.EnrolleeSuppliesSubject)
            {
                certificateAttribute = templateInfo.UserScope ? "userPrincipalName" : "dNSName";
                dsAttribute = templateInfo.UserScope ? "userPrincipalName" : "dNSHostName";
                objectCategory = templateInfo.UserScope ? "user" : "computer";
            }

            var identity = result.Identities.FirstOrDefault(x => x.Key.Equals(certificateAttribute)).Value;

            if (string.IsNullOrEmpty(identity))
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.DirVal_No_Cert_Identity, certificateAttribute));
                return result;
            }

            try
            {
                var dsObject = new ActiveDirectoryObject(_forestRootDomain, dsAttribute, identity, objectCategory, dsMapping.SearchRoot);

                return VerifyRequest(result, requestPolicy, dsObject);
            }
            catch (Exception ex)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, ex.Message);
                return result;
            }
        }

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
            CertificateRequestPolicy requestPolicy, ActiveDirectoryObject dsObject)
        {
            var dsMapping = requestPolicy.DirectoryServicesMapping;

            #region Process enablement status of the account

            if (dsObject.UserAccountControl.HasFlag(UserAccountControl.ACCOUNTDISABLE) &&
                !dsMapping.PermitDisabledAccounts)
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
                            string.Format(LocalizedStrings.DirVal_Rdn_Invalid_Field, rdn.Field, dsObject.Name));
                    }

                    continue;
                }

                if (!dsObject.Attributes.ContainsKey(rdn.DirectoryServicesAttribute))
                {
                    if (rdn.Mandatory)
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                            string.Format(LocalizedStrings.DirVal_Rdn_Invalid_Directory_Attribute,
                                rdn.DirectoryServicesAttribute, rdn.Field, dsObject.Name));
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
                                rdn.DirectoryServicesAttribute, rdn.Field, dsObject.Name, RdnInfo[rdn.Field].MaxLength,
                                dsAttribute.Length));
                    }

                    continue;
                }

                result.Properties.Add(new KeyValuePair<string, string>(RdnInfo[rdn.Field].NameProperty, dsAttribute));
            }

            #endregion

            #region Process SID certificate extension construction

            if (requestPolicy.SecurityIdentifierExtension.Equals("Add", COMPARISON))
            {
                var sidExt = new CX509ExtensionSecurityIdentifier();
                sidExt.InitializeEncode(dsObject.SecurityIdentifier);

                result.Extensions.Add(WinCrypt.szOID_DS_CA_SECURITY_EXT, Convert.ToBase64String(sidExt.RawData()));
            }

            #endregion

            return result;
        }
    }
}