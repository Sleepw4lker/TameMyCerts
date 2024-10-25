// Copyright 2021-2023 Uwe Gradenegger <uwe@gradenegger.eu>

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
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.X509;

namespace TameMyCerts.Validators
{
    /// <summary>
    ///     This validator is for everything that depends on binding a requested identity to an Active Directory object.
    /// </summary>
    internal class DirectoryServiceValidator
    {
        private const StringComparison Comparison = StringComparison.InvariantCultureIgnoreCase;
        private readonly string _forestRootDomain;

        public DirectoryServiceValidator(bool forTesting = false)
        {
            // DirectoryServiceValidator gets instanced only once, thus this is more efficient than enumerating this each time an ActiveDirectoryObject is instanced
            if (!forTesting)
            {
                _forestRootDomain = Forest.GetCurrentForest().Name;
            }
        }

        public CertificateRequestValidationResult GetMappedActiveDirectoryObject(
            CertificateRequestValidationResult result,
            CertificateRequestPolicy policy, CertificateDatabaseRow dbRow, CertificateTemplate template,
            out ActiveDirectoryObject dsObject)
        {
            dsObject = null;

            if (result.DeniedForIssuance || null == policy.DirectoryServicesMapping)
            {
                return result;
            }

            var dsMapping = policy.DirectoryServicesMapping;

            var certificateAttribute = dsMapping.CertificateAttribute;
            var dsAttribute = dsMapping.DirectoryServicesAttribute;
            var objectCategory = dsMapping.ObjectCategory;

            if (!template.EnrolleeSuppliesSubject)
            {
                certificateAttribute = template.UserScope ? "userPrincipalName" : "dNSName";
                dsAttribute = template.UserScope ? "userPrincipalName" : "dNSHostName";
                objectCategory = template.UserScope ? "user" : "computer";
            }

            var identities = dbRow.GetIdentities(template.EnrolleeSuppliesSubject,
                template.UserScope);

            var identity = identities.FirstOrDefault(x => x.Key.Equals(certificateAttribute)).Value;

            if (string.IsNullOrEmpty(identity))
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.DirVal_No_Cert_Identity, certificateAttribute));
                return result;
            }

            try
            {
                dsObject = new ActiveDirectoryObject(_forestRootDomain, dsAttribute, identity, objectCategory,
                    dsMapping.SearchRoot);
            }
            catch (Exception ex)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, ex.Message);
            }

            return result;
        }

        // This method is intended to be called from unit tests and the other Initialize method. It takes a given AD object to work with.
        public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
            CertificateRequestPolicy policy, ActiveDirectoryObject dsObject)
        {
            if (result.DeniedForIssuance || null == policy.DirectoryServicesMapping || null == dsObject)
            {
                return result;
            }

            var dsMapping = policy.DirectoryServicesMapping;

            #region Process enablement status of the account

            if (dsObject.UserAccountControl.HasFlag(UserAccountControl.ACCOUNTDISABLE) &&
                !dsMapping.PermitDisabledAccounts)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.DirVal_Account_Disabled, dsMapping.ObjectCategory,
                        dsObject.DistinguishedName));
                return result;
            }

            #endregion

            #region Process patterns for directory object attributes

            foreach (var rule in dsMapping.DirectoryObjectRules)
            {
                if (!dsObject.Attributes.ContainsKey(rule.DirectoryServicesAttribute))
                {
                    if (rule.Mandatory)
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                            string.Format(LocalizedStrings.DirVal_Invalid_Rule_Attribute,
                                rule.DirectoryServicesAttribute,
                                dsObject.DistinguishedName));
                    }

                    continue;
                }

                if (rule.Patterns.Any(pattern => pattern.Action.Equals("Allow", Comparison)) && !rule.Patterns
                        .Where(pattern => pattern.Action.Equals("Allow", Comparison))
                        .Any(pattern => pattern.IsMatch(dsObject.Attributes[rule.DirectoryServicesAttribute])))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                        string.Format(LocalizedStrings.DirVal_No_Match,
                            dsObject.Attributes[rule.DirectoryServicesAttribute], dsObject.DistinguishedName));
                }

                if (rule.Patterns.Any(pattern => pattern.Action.Equals("Deny", Comparison)))
                {
                    foreach (var pattern in rule.Patterns
                                 .Where(pattern => pattern.Action.Equals("Deny", Comparison))
                                 .Where(pattern =>
                                     pattern.IsMatch(dsObject.Attributes[rule.DirectoryServicesAttribute], true)))
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                            string.Format(LocalizedStrings.DirVal_Disallow_Match,
                                dsObject.Attributes[rule.DirectoryServicesAttribute], pattern.Expression,
                                dsObject.DistinguishedName));
                    }
                }
            }

            #endregion

            #region Process organizational unit memberships

            if (dsMapping.AllowedOrganizationalUnits.Any() &&
                !dsMapping.AllowedOrganizationalUnits.Any(s =>
                    dsObject.DistinguishedName.EndsWith($",{s}", Comparison)))
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.DirVal_No_Match_OU, dsMapping.ObjectCategory,
                        dsObject.DistinguishedName));
            }

            if (dsMapping.DisallowedOrganizationalUnits.Any())
            {
                foreach (var ou in dsMapping.DisallowedOrganizationalUnits.Where(s =>
                             dsObject.DistinguishedName.EndsWith($",{s}", Comparison)))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                        string.Format(LocalizedStrings.DirVal_Disallow_Match_OU, dsMapping.ObjectCategory,
                            dsObject.DistinguishedName, ou));
                }
            }

            #endregion

            #region Process security group memberships

            if (dsMapping.AllowedSecurityGroups.Any())
            {
                var matches = dsObject.MemberOf.Count(group =>
                    dsMapping.AllowedSecurityGroups.Any(s => s.Equals(group, Comparison)));

                if (matches == 0)
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                        LocalizedStrings.DirVal_Account_Groups_Not_Allowed,
                        dsMapping.ObjectCategory, dsObject.DistinguishedName));
                }
            }

            if (dsMapping.DisallowedSecurityGroups.Any())
            {
                foreach (var group in dsObject.MemberOf.Where(group =>
                             dsMapping.DisallowedSecurityGroups.Any(s => s.Equals(group, Comparison))))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                        LocalizedStrings.DirVal_Account_Groups_Disallowed,
                        dsMapping.ObjectCategory, dsObject.DistinguishedName, group));
                }
            }

            #endregion

            #region Supplement Service Principal Names (if any)

            if (dsMapping.SupplementServicePrincipalNames)
            {
                foreach (var identity in from spn in dsObject.ServicePrincipalNames
                         let prefixes = new List<string> { "host", "termsrv", "http", "wsman" }
                         let index = spn.IndexOf("/", Comparison)
                         where prefixes.Contains(spn.Substring(0, index), StringComparer.InvariantCultureIgnoreCase)
                         select spn.Substring(index + 1)
                         into identity
                         select identity)
                {
                    if (policy.SupplementUnqualifiedNames ||
                        (!policy.SupplementUnqualifiedNames && identity.Contains(".")))
                    {
                        result.SubjectAlternativeNameExtension.AddDnsName(identity);
                    }
                }
            }

            #endregion

            #region Process SID certificate extension construction

            if (policy.SecurityIdentifierExtension.Equals("Add", Comparison))
            {
                var sidExt = new X509CertificateExtensionSecurityIdentifier(dsObject.SecurityIdentifier);

                result.AddCertificateExtension(WinCrypt.szOID_NTDS_CA_SECURITY_EXT, sidExt.RawData);
            }

            #endregion

            #region Process SID certificate URI construction

            if (dsMapping.AddSidUniformResourceIdentifier)
            {
                result.SubjectAlternativeNameExtension.AddUniformResourceIdentifier(
                    $"tag:microsoft.com,2022-09-14:sid:{dsObject.SecurityIdentifier}");
            }

            #endregion

            #region Process Maximum password age
            if (dsMapping.MaximumPasswordAge > 0)
            {
                if (!(dsObject.Attributes.ContainsKey("pwdlastset")))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                        LocalizedStrings.DirVal_Account_Password_failed_to_parse, dsMapping.MaximumPasswordAge));
                }
                try
                {
                    long.TryParse(dsObject.Attributes["pwdlastSet"], out long pwdLastSetLong);
                    UInt32 PasswordAge = (UInt32)DateTime.UtcNow.Subtract(DateTime.FromFileTimeUtc(pwdLastSetLong)).TotalMinutes;
                    Console.WriteLine($"Password age: {PasswordAge}");
                    if (dsMapping.MaximumPasswordAge < PasswordAge)
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                        LocalizedStrings.DirVal_Account_Password_to_old, dsMapping.MaximumPasswordAge));
                    }
                }
                catch
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
    LocalizedStrings.DirVal_Account_Password_failed_to_parse, dsMapping.MaximumPasswordAge));
                }
            }
            #endregion
            return result;
        }
    }
}