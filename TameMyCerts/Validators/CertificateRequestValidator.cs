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
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using CERTENROLLLib;
using TameMyCerts.ClassExtensions;
using TameMyCerts.Enums;
using TameMyCerts.Models;

namespace TameMyCerts.Validators
{
    internal class CertificateRequestValidator
    {
        private const StringComparison COMPARISON = StringComparison.InvariantCultureIgnoreCase;

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
            CertificateRequestPolicy requestPolicy, CertificateTemplateInfo.Template templateInfo, string request)
        {
            return VerifyRequest(result, requestPolicy, templateInfo, request, CertCli.CR_IN_PKCS10);
        }

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
            CertificateRequestPolicy requestPolicy, CertificateTemplateInfo.Template templateInfo, byte[] request,
            int requestType)
        {
            return VerifyRequest(result, requestPolicy, templateInfo, Convert.ToBase64String(request), requestType);
        }

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
            CertificateRequestPolicy requestPolicy, CertificateTemplateInfo.Template templateInfo, string request,
            int requestType)
        {
            result.AuditOnly = requestPolicy.AuditOnly;

            // Early binding would raise an E_NOINTERFACE exception on Windows 2012 R2 and earlier
            var certificateRequestPkcs10 =
                (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                    Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));

            #region Parse the certificate request, extract inner PKCS#10 request if necessary

            if (!certificateRequestPkcs10.TryInitializeFromInnerRequest(request, requestType))
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Err_Parse_Request, requestType));
                Marshal.ReleaseComObject(certificateRequestPkcs10);
                return result;
            }

            #endregion

            #region Process rules for cryptographic providers

            if (requestPolicy.AllowedCryptoProviders.Count > 0 ||
                requestPolicy.DisallowedCryptoProviders.Count > 0)
            {
                if (result.RequestAttributes.TryGetValue("RequestCSPProvider", out var requestCspProvider))
                {
                    if (requestPolicy.AllowedCryptoProviders.Count > 0 && !requestPolicy.AllowedCryptoProviders.Any(s =>
                            s.Equals(requestCspProvider, COMPARISON)))
                    {
                        result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Crypto_Provider_Not_Allowed,
                            requestCspProvider));
                    }

                    if (requestPolicy.DisallowedCryptoProviders.Any(s =>
                            s.Equals(requestCspProvider, COMPARISON)))
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
                    Marshal.ReleaseComObject(certificateRequestPkcs10);
                    return result;
                }
            }

            #endregion

            #region Process rules for the process name

            if (requestPolicy.AllowedProcesses.Count > 0 ||
                requestPolicy.DisallowedProcesses.Count > 0)
            {
                if (certificateRequestPkcs10.GetInlineRequestAttributeList()
                    .TryGetValue("ProcessName", out var processName))
                {
                    if (requestPolicy.AllowedProcesses.Count > 0 && !requestPolicy.AllowedProcesses.Any(s =>
                            s.Equals(processName, COMPARISON)))
                    {
                        result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Process_Not_Allowed,
                            processName));
                    }

                    if (requestPolicy.DisallowedProcesses.Any(s =>
                            s.Equals(processName, COMPARISON)))
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
                    Marshal.ReleaseComObject(certificateRequestPkcs10);
                    return result;
                }
            }

            #endregion

            #region Process rules for key attributes

            if (requestPolicy.KeyAlgorithm != certificateRequestPkcs10.GetKeyAlgorithmName())
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Key_Pair_Mismatch,
                    requestPolicy.KeyAlgorithm));
            }

            if (certificateRequestPkcs10.PublicKey.Length < requestPolicy.MinimumKeyLength)
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Key_Too_Small,
                    certificateRequestPkcs10.PublicKey.Length, requestPolicy.MinimumKeyLength));
            }

            if (requestPolicy.MaximumKeyLength > 0 && certificateRequestPkcs10.PublicKey.Length >
                requestPolicy.MaximumKeyLength)
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Key_Too_Large,
                    certificateRequestPkcs10.PublicKey.Length, requestPolicy.MaximumKeyLength));
            }

            // Abort here to trigger proper error code
            if (result.DeniedForIssuance)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_KEY_LENGTH);
                Marshal.ReleaseComObject(certificateRequestPkcs10);
                return result;
            }

            #endregion

            if (templateInfo.EnrolleeSuppliesSubject)
            {
                #region Process Subject Relative Distinguished Names

                if (!certificateRequestPkcs10.TryGetSubjectRdnList(out var subjectRdnList))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_BAD_REQUESTSUBJECT,
                        LocalizedStrings.ReqVal_Err_Parse_SubjectDn);
                    Marshal.ReleaseComObject(certificateRequestPkcs10);
                    return result;
                }

                result.Identities.AddRange(subjectRdnList);

                if (!VerifySubject(subjectRdnList, requestPolicy.Subject,
                        out var subjectVerificationDescription))
                {
                    result.SetFailureStatus(WinError.CERT_E_INVALID_NAME, subjectVerificationDescription);
                }

                #endregion

                #region Process Subject Alternative Names

                if (!certificateRequestPkcs10.TryGetSubjectAlternativeNameList(out var subjectAltNameList))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_BAD_REQUESTSUBJECT,
                        string.Format(LocalizedStrings.ReqVal_Err_Parse_San, requestType));
                    Marshal.ReleaseComObject(certificateRequestPkcs10);
                    return result;
                }

                result.Identities.AddRange(subjectAltNameList);

                if (!VerifySubject(subjectAltNameList, requestPolicy.SubjectAlternativeName,
                        out var subjectAltNameVerificationDescription))
                {
                    result.SetFailureStatus(WinError.CERT_E_INVALID_NAME, subjectAltNameVerificationDescription);
                }

                #endregion

                #region Process request extensions

                if (certificateRequestPkcs10.HasExtension(WinCrypt.szOID_DS_CA_SECURITY_EXT))
                {
                    if (requestPolicy.SecurityIdentifierExtension.Equals("Deny", COMPARISON))
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                            string.Format(LocalizedStrings.ReqVal_Forbidden_Extensions,
                                WinCrypt.szOID_DS_CA_SECURITY_EXT, nameof(WinCrypt.szOID_DS_CA_SECURITY_EXT)));
                    }

                    if (requestPolicy.SecurityIdentifierExtension.Equals("Remove", COMPARISON))
                    {
                        result.DisabledExtensions.Add(WinCrypt.szOID_DS_CA_SECURITY_EXT);
                    }
                }

                #endregion

                #region Supplement DNS names (and IP addresses) from commonName to Subject Alternative Name

                if (requestPolicy.SupplementDnsNames &&
                    !certificateRequestPkcs10.HasExtension(WinCrypt.szOID_SUBJECT_ALT_NAME2))
                {
                    var uriHostNameTypes = new List<UriHostNameType>
                        {UriHostNameType.Dns, UriHostNameType.IPv4, UriHostNameType.IPv6};

                    var identities = subjectRdnList.Where(keyValuePair => keyValuePair.Key.Equals("commonName"))
                        .Where(keyValuePair => uriHostNameTypes.Contains(Uri.CheckHostName(keyValuePair.Value)))
                        .ToList();

                    if (identities.Count > 0)
                    {
                        var alternativeNames = new CAlternativeNames();

                        foreach (var identity in identities.Select(x => x.Value))
                        {
                            var alternativeName = new CAlternativeName();

                            switch (Uri.CheckHostName(identity))
                            {
                                case UriHostNameType.Dns:
                                    alternativeName.InitializeFromString(
                                        AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME,
                                        identity);
                                    break;

                                case UriHostNameType.IPv4:
                                case UriHostNameType.IPv6:
                                    alternativeName.InitializeFromRawData(
                                        AlternativeNameType.XCN_CERT_ALT_NAME_IP_ADDRESS,
                                        EncodingType.XCN_CRYPT_STRING_BASE64,
                                        Convert.ToBase64String(IPAddress.Parse(identity).GetAddressBytes()));
                                    break;
                            }

                            alternativeNames.Add(alternativeName);
                            Marshal.ReleaseComObject(alternativeName);
                        }

                        var extensionAlternativeNames = new CX509ExtensionAlternativeNames();

                        // Note that it is not necessary for the extension being marked critical as we still have the identities in commonName
                        extensionAlternativeNames.InitializeEncode(alternativeNames);

                        Marshal.ReleaseComObject(alternativeNames);

                        result.Extensions.Add(WinCrypt.szOID_SUBJECT_ALT_NAME2,
                            extensionAlternativeNames.get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64)
                                .Replace(Environment.NewLine, string.Empty));

                        Marshal.ReleaseComObject(extensionAlternativeNames);
                    }
                }

                #endregion
            }

            #region Set fixed expiration time

            result.SetNotAfter(requestPolicy.NotAfter);

            #endregion

            Marshal.ReleaseComObject(certificateRequestPkcs10);
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
                    keyValuePair.Key.Equals(subjectRule.Field, COMPARISON));

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
                    subjectRule.Field.Equals(subject.Key, COMPARISON));

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
                        .Where(pattern => pattern.Action.Equals("Allow", COMPARISON))
                        .Any(pattern => pattern.IsMatch(subject.Value)))
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_No_Match, subject.Value,
                        subject.Key));
                }

                description.AddRange(policyItem.Patterns
                    .Where(pattern => pattern.Action.Equals("Deny", COMPARISON))
                    .Where(pattern => pattern.IsMatch(subject.Value, true))
                    .Select(pattern => string.Format(LocalizedStrings.ReqVal_Disallow_Match, subject.Value,
                        pattern.Expression, subject.Key)));
            }

            #endregion

            return description.Count == 0;
        }
    }
}