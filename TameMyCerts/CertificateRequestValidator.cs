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

namespace TameMyCerts
{
    public class CertificateRequestValidator
    {
        private static readonly StringComparison StringComparison = StringComparison.InvariantCultureIgnoreCase;

        public CertificateRequestValidationResult VerifyRequest(string certificateRequest,
            CertificateRequestPolicy certificateRequestPolicy, CertificateTemplateInfo.Template templateInfo)
        {
            return VerifyRequest(certificateRequest, certificateRequestPolicy, templateInfo, CertCli.CR_IN_PKCS10,
                new Dictionary<string, string>());
        }

        public CertificateRequestValidationResult VerifyRequest(string certificateRequest,
            CertificateRequestPolicy certificateRequestPolicy, CertificateTemplateInfo.Template templateInfo,
            int requestType)
        {
            return VerifyRequest(certificateRequest, certificateRequestPolicy, templateInfo, requestType,
                new Dictionary<string, string>());
        }

        public CertificateRequestValidationResult VerifyRequest(string certificateRequest,
            CertificateRequestPolicy certificateRequestPolicy, CertificateTemplateInfo.Template templateInfo,
            Dictionary<string, string> requestAttributeList)
        {
            return VerifyRequest(certificateRequest, certificateRequestPolicy, templateInfo, CertCli.CR_IN_PKCS10,
                requestAttributeList);
        }

        public CertificateRequestValidationResult VerifyRequest(string certificateRequest,
            CertificateRequestPolicy certificateRequestPolicy, CertificateTemplateInfo.Template templateInfo,
            int requestType, Dictionary<string, string> requestAttributeList)
        {
            var result = new CertificateRequestValidationResult(certificateRequestPolicy.AuditOnly,
                certificateRequestPolicy.NotAfter);

            // In case something went wrong with parsing policy values
            if (result.DeniedForIssuance)
            {
                return result;
            }

            // Early binding would raise an E_NOINTERFACE exception on Windows 2012 R2 and earlier
            var certificateRequestPkcs10 =
                (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                    Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));

            #region Parse the certificate request, extract inner PKCS#10 request if necessary

            if (!certificateRequestPkcs10.TryInitializeFromInnerRequest(certificateRequest, requestType))
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Err_Parse_Request, requestType));
                Marshal.ReleaseComObject(certificateRequestPkcs10);
                return result;
            }

            #endregion

            #region Process rules for cryptographic providers

            if (certificateRequestPolicy.AllowedCryptoProviders.Count > 0 ||
                certificateRequestPolicy.DisallowedCryptoProviders.Count > 0)
            {
                if (requestAttributeList.TryGetValue("RequestCSPProvider", out var requestCspProvider))
                {
                    if (!certificateRequestPolicy.AllowedCryptoProviders.Any(s =>
                            s.Equals(requestCspProvider, StringComparison)))
                    {
                        result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Crypto_Provider_Not_Allowed,
                            requestCspProvider));
                    }

                    if (certificateRequestPolicy.DisallowedCryptoProviders.Any(s =>
                            s.Equals(requestCspProvider, StringComparison)))
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

            if (certificateRequestPolicy.AllowedProcesses.Count > 0 ||
                certificateRequestPolicy.DisallowedProcesses.Count > 0)
            {
                if (certificateRequestPkcs10.GetInlineRequestAttributeList()
                    .TryGetValue("ProcessName", out var processName))
                {
                    if (!certificateRequestPolicy.AllowedProcesses.Any(s =>
                            s.Equals(processName, StringComparison)))
                    {
                        result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Process_Not_Allowed,
                            processName));
                    }

                    if (certificateRequestPolicy.DisallowedProcesses.Any(s =>
                            s.Equals(processName, StringComparison)))
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

            if (templateInfo.EnrolleeSuppliesSubject)
            {
                #region Process rules for key attributes

                if (certificateRequestPolicy.KeyAlgorithm != certificateRequestPkcs10.GetKeyAlgorithmName())
                {
                    result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Key_Pair_Mismatch,
                        certificateRequestPolicy.KeyAlgorithm));
                }

                if (certificateRequestPkcs10.PublicKey.Length < certificateRequestPolicy.MinimumKeyLength)
                {
                    result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Key_Too_Small,
                        certificateRequestPkcs10.PublicKey.Length, certificateRequestPolicy.MinimumKeyLength));
                }

                if (certificateRequestPolicy.MaximumKeyLength > 0 && certificateRequestPkcs10.PublicKey.Length >
                    certificateRequestPolicy.MaximumKeyLength)
                {
                    result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Key_Too_Large,
                        certificateRequestPkcs10.PublicKey.Length, certificateRequestPolicy.MaximumKeyLength));
                }

                // Abort here to trigger proper error code
                if (result.DeniedForIssuance)
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_KEY_LENGTH);
                    Marshal.ReleaseComObject(certificateRequestPkcs10);
                    return result;
                }

                #endregion

                #region Process Subject Relative Distinguished Names

                if (!certificateRequestPkcs10.TryGetSubjectRdnList(out var subjectRdnList))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_BAD_REQUESTSUBJECT,
                        LocalizedStrings.ReqVal_Err_Parse_SubjectDn);
                    Marshal.ReleaseComObject(certificateRequestPkcs10);
                    return result;
                }

                result.Identities.AddRange(subjectRdnList);

                if (!VerifySubject(subjectRdnList, certificateRequestPolicy.Subject,
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

                if (!VerifySubject(subjectAltNameList, certificateRequestPolicy.SubjectAlternativeName,
                        out var subjectAltNameVerificationDescription))
                {
                    result.SetFailureStatus(WinError.CERT_E_INVALID_NAME, subjectAltNameVerificationDescription);
                }

                #endregion

                #region Process request extensions

                if (certificateRequestPolicy.SecurityIdentifierExtension.Equals("Deny",
                        StringComparison) &&
                    certificateRequestPkcs10.HasExtension(WinCrypt.szOID_DS_CA_SECURITY_EXT))
                {
                    result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Forbidden_Extensions,
                        WinCrypt.szOID_DS_CA_SECURITY_EXT));
                }

                #endregion

                #region Supplement DNS names (and IP addresses) from commonName to Subject Alternative Name

                if (certificateRequestPolicy.SupplementDnsNames &&
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
                    keyValuePair.Key.Equals(subjectRule.Field, StringComparison));

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
                    subjectRule.Field.Equals(subject.Key, StringComparison));

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
                        .Where(pattern => pattern.Action.Equals("Allow", StringComparison))
                        .Any(pattern => pattern.IsMatch(subject.Value)))
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_No_Match, subject.Value,
                        subject.Key));
                }

                description.AddRange(policyItem.Patterns
                    .Where(pattern => pattern.Action.Equals("Deny", StringComparison))
                    .Where(pattern => pattern.IsMatch(subject.Value, true))
                    .Select(pattern => string.Format(LocalizedStrings.ReqVal_Disallow_Match, subject.Value,
                        pattern.Expression, subject.Key)));
            }

            #endregion

            return description.Count == 0;
        }
    }
}