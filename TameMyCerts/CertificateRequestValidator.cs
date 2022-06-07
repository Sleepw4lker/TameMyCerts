// Copyright 2021 Uwe Gradenegger

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
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using CERTENROLLLib;

namespace TameMyCerts
{
    public class CertificateRequestValidator
    {
        public CertificateRequestVerificationResult VerifyRequest(string certificateRequest,
            CertificateRequestPolicy certificateRequestPolicy, CertificateTemplateInfo.Template templateInfo,
            int requestType = CertCli.CR_IN_PKCS10, Dictionary<string, string> requestAttributeList = null)
        {
            var result = new CertificateRequestVerificationResult(certificateRequestPolicy.AuditOnly);

            #region Parse the certificate request, extract inner PKCS#10 request if necessary

            if (!TryExtractInnerRequest(certificateRequest, requestType, out var certificateRequestPkcs10))
            {
                result.Success = false;
                result.Description.Add(string.Format(LocalizedStrings.ReqVal_Err_Parse_Request, requestType));
                result.StatusCode = WinError.NTE_FAIL;
                return result;
            }

            #endregion

            #region Extract inline request attributes

            var inlineRequestAttributeList = certificateRequestPkcs10.GetInlineRequestAttributeList();

            #endregion

            #region Process rules for cryptographic providers

            if ((certificateRequestPolicy.AllowedCryptoProviders != null &&
                 certificateRequestPolicy.AllowedCryptoProviders.Count > 0) ||
                (certificateRequestPolicy.DisallowedCryptoProviders != null &&
                 certificateRequestPolicy.DisallowedCryptoProviders.Count > 0))
            {
                if (requestAttributeList != null &&
                    requestAttributeList.Any(x =>
                        x.Key.Equals("RequestCSPProvider", StringComparison.InvariantCultureIgnoreCase)))
                {
                    var cryptoProvider = requestAttributeList.FirstOrDefault(x =>
                            x.Key.Equals("RequestCSPProvider", StringComparison.InvariantCultureIgnoreCase))
                        .Value;

                    if (certificateRequestPolicy.AllowedCryptoProviders != null &&
                        !certificateRequestPolicy.AllowedCryptoProviders.Any(x =>
                            x.Equals(cryptoProvider, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Crypto_Provider_Not_Allowed,
                            cryptoProvider));
                    }

                    if (certificateRequestPolicy.DisallowedCryptoProviders != null &&
                        certificateRequestPolicy.DisallowedCryptoProviders.Any(x =>
                            x.Equals(cryptoProvider, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Crypto_Provider_Disallowed,
                            cryptoProvider));
                    }
                }
                else
                {
                    result.Success = false;
                    result.Description.Add(LocalizedStrings.ReqVal_Crypto_Provider_Unknown);
                }

                // Abort here to trigger proper error code
                if (result.Success == false)
                {
                    result.StatusCode = WinError.CERTSRV_E_TEMPLATE_DENIED;
                    return result;
                }
            }

            #endregion

            #region Process rules for the process name

            if ((certificateRequestPolicy.AllowedProcesses != null &&
                 certificateRequestPolicy.AllowedProcesses.Count > 0) ||
                (certificateRequestPolicy.DisallowedProcesses != null &&
                 certificateRequestPolicy.DisallowedProcesses.Count > 0))
            {
                if (inlineRequestAttributeList.TryGetValue("processName", out var processName))
                {
                    if (certificateRequestPolicy.AllowedProcesses != null &&
                        !certificateRequestPolicy.AllowedProcesses.Any(x =>
                            x.Equals(processName, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Process_Not_Allowed,
                            processName));
                    }

                    if (certificateRequestPolicy.DisallowedProcesses != null &&
                        certificateRequestPolicy.DisallowedProcesses.Any(x =>
                            x.Equals(processName, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Process_Disallowed,
                            processName));
                    }
                }
                else
                {
                    result.Success = false;
                    result.Description.Add(LocalizedStrings.ReqVal_Process_Unknown);
                }

                // Abort here to trigger proper error code
                if (result.Success == false)
                {
                    result.StatusCode = WinError.CERTSRV_E_TEMPLATE_DENIED;
                    return result;
                }
            }

            #endregion

            if (templateInfo.EnrolleeSuppliesSubject)
            {
                #region Process rules for key attributes

                // Verify Key Algorithm
                string keyAlgorithm;

                switch (certificateRequestPkcs10.PublicKey.Algorithm.Value)
                {
                    case WinCrypt.szOID_ECC_PUBLIC_KEY:
                        keyAlgorithm = "ECC";
                        break;
                    case WinCrypt.szOID_RSA_RSA:
                        keyAlgorithm = "RSA";
                        break;
                    default:
                        keyAlgorithm = LocalizedStrings.Unknown;
                        break;
                }

                if (certificateRequestPolicy.KeyAlgorithm != keyAlgorithm)
                {
                    result.Success = false;
                    result.Description.Add(string.Format(LocalizedStrings.ReqVal_Key_Pair_Mismatch,
                        keyAlgorithm, certificateRequestPolicy.KeyAlgorithm));
                }

                if (certificateRequestPkcs10.PublicKey.Length < certificateRequestPolicy.MinimumKeyLength)
                {
                    result.Success = false;
                    result.Description.Add(string.Format(LocalizedStrings.ReqVal_Key_Too_Small,
                        certificateRequestPkcs10.PublicKey.Length, certificateRequestPolicy.MinimumKeyLength));
                }

                if (certificateRequestPolicy.MaximumKeyLength > 0)
                {
                    if (certificateRequestPkcs10.PublicKey.Length > certificateRequestPolicy.MaximumKeyLength)
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Key_Too_Large,
                            certificateRequestPkcs10.PublicKey.Length, certificateRequestPolicy.MaximumKeyLength));
                    }
                }

                // Abort here to trigger proper error code
                if (result.Success == false)
                {
                    result.StatusCode = WinError.CERTSRV_E_KEY_LENGTH;
                    return result;
                }

                #endregion

                #region Extract Subject Distinguished Name

                if (!certificateRequestPkcs10.TryGetSubjectRdnList(out var subjectRdnList))
                {
                    result.Success = false;
                    result.Description.Add(LocalizedStrings.ReqVal_Err_Parse_SubjectDn);
                    result.StatusCode = WinError.CERTSRV_E_BAD_REQUESTSUBJECT;
                    return result;
                }

                #endregion

                #region Process certificate request extensions (mainly Subject Alternative Name)

                if (!certificateRequestPkcs10.TryGetSubjectAlternativeNameList(out var subjectAltNameList))
                {
                    result.Success = false;
                    result.Description.Add(string.Format(LocalizedStrings.ReqVal_Err_Parse_San, requestType));
                    result.StatusCode = WinError.NTE_FAIL;
                    return result;
                }

                if (certificateRequestPkcs10.HasForbiddenExtensions())
                {
                    result.Success = false;
                    result.Description.Add(string.Format(LocalizedStrings.ReqVal_Forbidden_Extensions, requestType));
                    result.StatusCode = WinError.NTE_FAIL;
                }

                #endregion

                #region Process rules for name constraints

                if (!VerifySubject(subjectRdnList, certificateRequestPolicy.Subject,
                        out var subjectVerificationDescription))
                {
                    result.Success = false;
                    result.Description.AddRange(subjectVerificationDescription);
                    result.StatusCode = WinError.CERT_E_INVALID_NAME;
                }

                if (!VerifySubject(subjectAltNameList, certificateRequestPolicy.SubjectAlternativeName,
                        out var subjectAltNameVerificationDescription))
                {
                    result.Success = false;
                    result.Description.AddRange(subjectAltNameVerificationDescription);
                    result.StatusCode = WinError.CERT_E_INVALID_NAME;
                }

                #endregion
            }

            #region Process fixed certificate expiration date

            if (certificateRequestPolicy.NotAfter != null)
            {
                // The "o" standard format specifier corresponds to the "yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fffffffzzz" custom format string for DateTimeOffset values.
                // see https://docs.microsoft.com/en-us/dotnet/standard/base-types/standard-date-and-time-format-strings#the-round-trip-o-o-format-specifier
                if (DateTimeOffset.TryParseExact(certificateRequestPolicy.NotAfter, "o",
                        CultureInfo.InvariantCulture.DateTimeFormat,
                        DateTimeStyles.AssumeUniversal, out var notAfter))
                {
                    // Deny if the configured expiration date is over already
                    if (notAfter < DateTimeOffset.UtcNow)
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Err_NotAfter_Passed,
                            notAfter.UtcDateTime));
                        result.StatusCode = WinError.NTE_FAIL;
                        return result;
                    }

                    result.NotAfter = notAfter;
                }
                else
                {
                    result.Success = false;
                    result.Description.Add(LocalizedStrings.ReqVal_Err_NotAfter_Invalid);
                    result.StatusCode = WinError.NTE_FAIL;
                    return result;
                }
            }

            #endregion

            return result;
        }

        private bool TryExtractInnerRequest(string certificateRequest, int requestType,
            out IX509CertificateRequestPkcs10 certificateRequestPkcs10)
        {
            // Short form would raise an E_NOINTERFACE exception on Windows 2012 R2 and earlier
            certificateRequestPkcs10 =
                (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                    Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));

            switch (requestType)
            {
                case CertCli.CR_IN_CMC:

                    var certificateRequestCmc =
                        (IX509CertificateRequestCmc) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestCmc"));

                    try
                    {
                        certificateRequestCmc.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        var innerRequest = certificateRequestCmc.GetInnerRequest(InnerRequestLevel.LevelInnermost);
                        certificateRequest = innerRequest.get_RawData();
                    }
                    catch
                    {
                        return false;
                    }

                    break;

                case CertCli.CR_IN_PKCS7:

                    var certificateRequestPkcs7 =
                        (IX509CertificateRequestPkcs7) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs7"));

                    try
                    {
                        certificateRequestPkcs7.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        var innerRequest = certificateRequestPkcs7.GetInnerRequest(InnerRequestLevel.LevelInnermost);
                        certificateRequest = innerRequest.get_RawData();
                    }
                    catch
                    {
                        return false;
                    }

                    break;
            }

            try
            {
                certificateRequestPkcs10.InitializeDecode(
                    certificateRequest,
                    EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                );
            }
            catch
            {
                return false;
            }

            return true;
        }

        private static bool VerifySubject(
            List<KeyValuePair<string, string>> subjectInfo, List<SubjectRule> subjectPolicy,
            out List<string> description)
        {
            description = new List<string>();
            var result = true;

            if (subjectInfo == null)
            {
                return false;
            }

            // Cycle through defined RDNs and compare to present RDNs
            foreach (var definedItem in subjectPolicy)
            {
                // Count the occurrences of the currently inspected defined RDN, if any
                var occurrences = subjectInfo.Count(x =>
                    x.Key.Equals(definedItem.Field, StringComparison.InvariantCultureIgnoreCase));

                // Deny if a RDN defined as mandatory is missing
                if (occurrences == 0 && definedItem.Mandatory)
                {
                    result = false;
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Missing, definedItem.Field));
                }

                // Deny if a RDN occurs too often
                if (occurrences > definedItem.MaxOccurrences)
                {
                    result = false;
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Count_Mismatch,
                        definedItem.Field, occurrences, definedItem.MaxOccurrences));
                }
            }

            foreach (var subjectItem in subjectInfo)
            {
                var policyItem = subjectPolicy.FirstOrDefault(x =>
                    x.Field.Equals(subjectItem.Key, StringComparison.InvariantCultureIgnoreCase));

                if (policyItem == null)
                {
                    // Deny if a RDN is found that is not defined (therefore it is forbidden)
                    result = false;
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Not_Allowed, subjectItem.Key));
                }
                else
                {
                    // Deny if the RDNs content deceeds the defined number of Characters
                    if (subjectItem.Value.Length < policyItem.MinLength)
                    {
                        result = false;
                        description.Add(string.Format(LocalizedStrings.ReqVal_Field_Too_Short, subjectItem.Value,
                            subjectItem.Key, policyItem.MinLength));
                    }

                    // Deny if the RDNs content exceeds defined number of Characters
                    if (subjectItem.Value.Length > policyItem.MaxLength)
                    {
                        result = false;
                        description.Add(string.Format(LocalizedStrings.ReqVal_Field_Too_Long, subjectItem.Value,
                            subjectItem.Key, policyItem.MaxLength));
                    }

                    // Process patterns
                    if (policyItem.Patterns == null)
                    {
                        result = false;
                        description.Add(string.Format(LocalizedStrings.ReqVal_Field_Not_Defined, subjectItem.Key));
                    }

                    #region Deny if there aren't any allowed matches

                    var matchFound = false;

                    foreach (var pattern in policyItem.Patterns.Where(x =>
                                 x.Action.Equals("Allow", StringComparison.InvariantCultureIgnoreCase)))
                    {
                        if (VerifyPattern(subjectItem.Value, pattern))
                        {
                            matchFound = true;
                            break;
                        }
                    }

                    if (!matchFound)
                    {
                        result = false;
                        description.Add(string.Format(LocalizedStrings.ReqVal_No_Match, subjectItem.Value,
                            subjectItem.Key));
                    }

                    #endregion

                    #region Deny if there is any disallowed match

                    foreach (var pattern in policyItem.Patterns.Where(x =>
                                 x.Action.Equals("Deny", StringComparison.InvariantCultureIgnoreCase)))
                    {
                        if (VerifyPattern(subjectItem.Value, pattern, true))
                        {
                            result = false;
                            description.Add(string.Format(LocalizedStrings.ReqVal_Disallow_Match,
                                subjectItem.Value, pattern.Expression, subjectItem.Key));
                        }
                    }

                    #endregion
                }
            }

            return result;
        }

        private static bool VerifyPattern(string term, Pattern pattern, bool matchOnError = false)
        {
            try
            {
                switch (pattern.TreatAs.ToLowerInvariant())
                {
                    case "regex":

                        var regEx = new Regex(@"" + pattern.Expression + "");
                        if (regEx.IsMatch(term))
                        {
                            return true;
                        }

                        break;

                    case "cidr":

                        var ipAddress = IPAddress.Parse(term);
                        if (ipAddress.IsInRange(pattern.Expression))
                        {
                            return true;
                        }

                        break;
                }
            }
            catch
            {
                // This ensures that failing to interpret the pattern will result in matching as a denied one
                if (matchOnError)
                {
                    return true;
                }
            }

            return false;
        }

        public class CertificateRequestVerificationResult
        {
            public CertificateRequestVerificationResult(bool auditOnly = false)
            {
                AuditOnly = auditOnly;
            }

            public DateTimeOffset NotAfter { get; set; } = DateTimeOffset.MinValue;
            public int StatusCode { get; set; } = WinError.ERROR_SUCCESS;
            public bool Success { get; set; } = true;
            public bool AuditOnly { get; }
            public List<string> Description { get; set; } = new List<string>();
        }
    }
}