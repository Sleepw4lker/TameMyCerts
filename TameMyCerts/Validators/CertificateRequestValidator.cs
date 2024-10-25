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
using System.Linq;
using System.Net;
using TameMyCerts.Enums;
using TameMyCerts.Models;

namespace TameMyCerts.Validators
{
    /// <summary>
    ///     This validator is for everything concerning the original certificate request.
    /// </summary>
    internal class CertificateRequestValidator
    {
        private const StringComparison Comparison = StringComparison.InvariantCultureIgnoreCase;

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
            CertificateRequestPolicy policy, CertificateDatabaseRow dbRow, CertificateTemplate template)
        {
            if (result.DeniedForIssuance)
            {
                return result;
            }

            #region Process rules for cryptographic providers

            if (policy.AllowedCryptoProviders.Count > 0 ||
                policy.DisallowedCryptoProviders.Count > 0)
            {
                if (dbRow.RequestAttributes.TryGetValue("RequestCSPProvider", out var requestCspProvider))
                {
                    if (policy.AllowedCryptoProviders.Count > 0 && !policy.AllowedCryptoProviders.Any(s =>
                            s.Equals(requestCspProvider, Comparison)))
                    {
                        result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Crypto_Provider_Not_Allowed,
                            requestCspProvider));
                    }

                    if (policy.DisallowedCryptoProviders.Any(s =>
                            s.Equals(requestCspProvider, Comparison)))
                    {
                        result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Crypto_Provider_Disallowed,
                            requestCspProvider));
                    }
                }
                else
                {
                    result.SetFailureStatus(LocalizedStrings.ReqVal_Crypto_Provider_Unknown);
                }

                // Abort here to trigger proper error code
                if (result.DeniedForIssuance)
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED);
                    return result;
                }
            }

            #endregion

            #region Process rules for the process name

            if (policy.AllowedProcesses.Count > 0 ||
                policy.DisallowedProcesses.Count > 0)
            {
                if (dbRow.InlineRequestAttributes.TryGetValue("ProcessName", out var processName))
                {
                    if (policy.AllowedProcesses.Count > 0 && !policy.AllowedProcesses.Any(s =>
                            s.Equals(processName, Comparison)))
                    {
                        result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Process_Not_Allowed,
                            processName));
                    }

                    if (policy.DisallowedProcesses.Any(s =>
                            s.Equals(processName, Comparison)))
                    {
                        result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Process_Disallowed,
                            processName));
                    }
                }
                else
                {
                    result.SetFailureStatus(LocalizedStrings.ReqVal_Process_Unknown);
                }

                // Abort here to trigger proper error code
                if (result.DeniedForIssuance)
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED);
                    return result;
                }
            }

            #endregion

            #region Process rules for key attributes

            if (template.KeyAlgorithmFamily != dbRow.KeyAlgorithm)
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Key_Pair_Mismatch,
                    Enum.GetName(typeof(KeyAlgorithmFamily), template.KeyAlgorithmFamily),
                    Enum.GetName(typeof(KeyAlgorithmFamily), dbRow.KeyAlgorithm)));
            }

            if (dbRow.KeyLength < policy.MinimumKeyLength)
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Key_Too_Small,
                    dbRow.KeyLength, policy.MinimumKeyLength));
            }

            if (policy.MaximumKeyLength > 0 && dbRow.KeyLength >
                policy.MaximumKeyLength)
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Key_Too_Large,
                    dbRow.KeyLength, policy.MaximumKeyLength));
            }

            // Abort here to trigger proper error code
            if (result.DeniedForIssuance)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_KEY_LENGTH);
                return result;
            }

            #endregion

            if (template.EnrolleeSuppliesSubject)
            {
                #region Process Subject Relative Distinguished Names

                var rdnList = policy.ReadSubjectFromRequest
                    ? dbRow.InlineSubjectRelativeDistinguishedNames
                    : dbRow.SubjectRelativeDistinguishedNames;

                if (!VerifySubject(rdnList, policy.Subject,
                        out var subjectVerificationDescription))
                {
                    result.SetFailureStatus(WinError.CERT_E_INVALID_NAME, subjectVerificationDescription);
                }

                #endregion

                #region Process Subject Alternative Names

                if (!VerifySubject(dbRow.SubjectAlternativeNames, policy.SubjectAlternativeName,
                        out var subjectAltNameVerificationDescription))
                {
                    result.SetFailureStatus(WinError.CERT_E_INVALID_NAME, subjectAltNameVerificationDescription);
                }

                #endregion

                #region Process request extensions

                if (dbRow.CertificateExtensions.ContainsKey(WinCrypt.szOID_NTDS_CA_SECURITY_EXT))
                {
                    if (policy.SecurityIdentifierExtension.Equals("Deny", Comparison))
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                            string.Format(LocalizedStrings.ReqVal_Forbidden_Extensions,
                                WinCrypt.szOID_NTDS_CA_SECURITY_EXT, nameof(WinCrypt.szOID_NTDS_CA_SECURITY_EXT)));
                    }

                    if (policy.SecurityIdentifierExtension.Equals("Remove", Comparison))
                    {
                        result.DisabledCertificateExtensions.Add(WinCrypt.szOID_NTDS_CA_SECURITY_EXT);
                    }
                }

                #endregion

                #region Supplement DNS names (and IP addresses) from commonName to Subject Alternative Name

                if (policy.SupplementDnsNames)
                {
                    var uriHostNameTypes = new List<UriHostNameType>
                        { UriHostNameType.Dns, UriHostNameType.IPv4, UriHostNameType.IPv6 };

                    var identities = dbRow.SubjectRelativeDistinguishedNames
                        .Where(keyValuePair => keyValuePair.Key.Equals(RdnTypes.CommonName))
                        .Where(keyValuePair => uriHostNameTypes.Contains(Uri.CheckHostName(keyValuePair.Value)))
                        .ToList();

                    if (identities.Count > 0)
                    {
                        foreach (var identity in identities.Select(x => x.Value))
                        {
                            switch (Uri.CheckHostName(identity))
                            {
                                case UriHostNameType.Dns:
                                    if (policy.SupplementUnqualifiedNames ||
                                        (!policy.SupplementUnqualifiedNames && identity.Contains(".")))
                                    {
                                        result.SubjectAlternativeNameExtension.AddDnsName(identity);
                                    }

                                    break;

                                case UriHostNameType.IPv4:
                                case UriHostNameType.IPv6:
                                    result.SubjectAlternativeNameExtension.AddIpAddress(IPAddress.Parse(identity));
                                    break;
                            }
                        }
                    }
                }

                #endregion
            }

            #region Set fixed expiration time

            result.SetNotAfter(policy.NotAfter);

            #endregion

            return result;
        }

        private static bool VerifySubject(
            List<KeyValuePair<string, string>> subjectList, List<SubjectRule> subjectRuleList,
            out List<string> description)
        {
            description = new List<string>();

            #region Search for missing mandatory fields or for fields that appear too often

            foreach (var subjectRule in subjectRuleList)
            {
                var occurrences = subjectList.Count(keyValuePair =>
                    keyValuePair.Key.Equals(subjectRule.Field, Comparison));

                if (occurrences == 0 && subjectRule.Mandatory)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Missing, subjectRule.Field));
                    continue;
                }

                if (occurrences > subjectRule.MaxOccurrences)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Count_Mismatch,
                        subjectRule.Field, occurrences, subjectRule.MaxOccurrences));
                }
            }

            #endregion

            #region Inspect fields and match against rules (if defined)

            foreach (var subject in subjectList)
            {
                var policyItem = subjectRuleList.FirstOrDefault(subjectRule =>
                    subjectRule.Field.Equals(subject.Key, Comparison));

                if (policyItem == null)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Not_Allowed, subject.Key));
                    continue;
                }

                if (policyItem.Patterns.Count == 0)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Not_Defined, subject.Key));
                    continue;
                }

                if (subject.Value.Length < policyItem.MinLength)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Too_Short, subject.Value,
                        subject.Key, policyItem.MinLength));
                }

                if (subject.Value.Length > policyItem.MaxLength)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Too_Long, subject.Value,
                        subject.Key, policyItem.MaxLength));
                }

                if (!policyItem.Patterns
                        .Where(pattern => pattern.Action.Equals("Allow", Comparison))
                        .Any(pattern => pattern.IsMatch(subject.Value)))
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_No_Match, subject.Value,
                        subject.Key));
                }

                description.AddRange(policyItem.Patterns
                    .Where(pattern => pattern.Action.Equals("Deny", Comparison))
                    .Where(pattern => pattern.IsMatch(subject.Value, true))
                    .Select(pattern => string.Format(LocalizedStrings.ReqVal_Disallow_Match, subject.Value,
                        pattern.Expression, subject.Key)));
            }

            #endregion

            return description.Count == 0;
        }
    }
}