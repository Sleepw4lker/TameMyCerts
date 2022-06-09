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
using System.Linq;
using System.Runtime.InteropServices;
using CERTENROLLLib;

namespace TameMyCerts
{
    public class CertificateRequestValidator
    {
        public CertificateRequestValidationResult VerifyRequest(string certificateRequest,
            CertificateRequestPolicy certificateRequestPolicy, CertificateTemplateInfo.Template templateInfo)
        {
            return VerifyRequest(certificateRequest, certificateRequestPolicy, templateInfo, CertCli.CR_IN_PKCS10,
                new Dictionary<string, string>());
        }

        public CertificateRequestValidationResult VerifyRequest(string certificateRequest,
            CertificateRequestPolicy certificateRequestPolicy, CertificateTemplateInfo.Template templateInfo,
            int requestType, Dictionary<string, string> requestAttributeList)
        {
            var result = new CertificateRequestValidationResult(certificateRequestPolicy.AuditOnly);

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
                    if (!certificateRequestPolicy.AllowedCryptoProviders.Any(x =>
                            x.Equals(requestCspProvider, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Crypto_Provider_Not_Allowed,
                            requestCspProvider));
                    }

                    if (certificateRequestPolicy.DisallowedCryptoProviders.Any(x =>
                            x.Equals(requestCspProvider, StringComparison.InvariantCultureIgnoreCase)))
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
                    .TryGetValue("processName", out var processName))
                {
                    if (!certificateRequestPolicy.AllowedProcesses.Any(x =>
                            x.Equals(processName, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Process_Not_Allowed,
                            processName));
                    }

                    if (certificateRequestPolicy.DisallowedProcesses.Any(x =>
                            x.Equals(processName, StringComparison.InvariantCultureIgnoreCase)))
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

                if (!VerifySubject(subjectAltNameList, certificateRequestPolicy.SubjectAlternativeName,
                        out var subjectAltNameVerificationDescription))
                {
                    result.SetFailureStatus(WinError.CERT_E_INVALID_NAME, subjectAltNameVerificationDescription);
                }

                #endregion

                #region Process forbidden extensions

                if (certificateRequestPkcs10.HasForbiddenExtensions())
                {
                    result.SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Forbidden_Extensions, requestType));
                }

                #endregion

            }

            #region Process fixed certificate expiration date

            result.SetNotAfter(certificateRequestPolicy.NotAfter);

            #endregion

            Marshal.ReleaseComObject(certificateRequestPkcs10);
            return result;
        }

        private static bool VerifySubject(
            List<KeyValuePair<string, string>> subjectInfoList, List<SubjectRule> subjectPolicy,
            out List<string> description)
        {
            description = new List<string>();

            foreach (var definedItem in subjectPolicy)
            {
                var occurrences = subjectInfoList.Count(keyValuePair =>
                    keyValuePair.Key.Equals(definedItem.Field, StringComparison.InvariantCultureIgnoreCase));

                if (occurrences == 0 && definedItem.Mandatory)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Missing, definedItem.Field));
                }

                if (occurrences > definedItem.MaxOccurrences)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Count_Mismatch,
                        definedItem.Field, occurrences, definedItem.MaxOccurrences));
                }
            }

            foreach (var subjectItem in subjectInfoList)
            {
                var policyItem = subjectPolicy.FirstOrDefault(x =>
                    x.Field.Equals(subjectItem.Key, StringComparison.InvariantCultureIgnoreCase));

                if (policyItem == null)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Not_Allowed, subjectItem.Key));
                    continue;
                }

                if (policyItem.Patterns.Count == 0)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Not_Defined, subjectItem.Key));
                    continue;
                }

                if (subjectItem.Value.Length < policyItem.MinLength)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Too_Short, subjectItem.Value,
                        subjectItem.Key, policyItem.MinLength));
                }

                if (subjectItem.Value.Length > policyItem.MaxLength)
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Field_Too_Long, subjectItem.Value,
                        subjectItem.Key, policyItem.MaxLength));
                }

                if (!policyItem.Patterns
                        .Where(pattern => pattern.Action.Equals("Allow", StringComparison.InvariantCultureIgnoreCase))
                        .Any(pattern => pattern.IsMatch(subjectItem.Value)))
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_No_Match, subjectItem.Value,
                        subjectItem.Key));
                }

                foreach (var pattern in policyItem.Patterns
                             .Where(pattern =>
                                 pattern.Action.Equals("Deny", StringComparison.InvariantCultureIgnoreCase))
                             .Where(pattern => pattern.IsMatch(subjectItem.Value, true)))
                {
                    description.Add(string.Format(LocalizedStrings.ReqVal_Disallow_Match,
                        subjectItem.Value, pattern.Expression, subjectItem.Key));
                }
            }

            return description.Count == 0;
        }
    }
}