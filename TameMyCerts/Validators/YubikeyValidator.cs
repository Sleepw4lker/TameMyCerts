﻿// Copyright 2021-2024 Uwe Gradenegger <uwe@gradenegger.eu>
// Copyright 2024 Oscar Virot <virot@virot.com>

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
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using TameMyCerts.ClassExtensions;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.X509;

namespace TameMyCerts.Validators
{
    /// <summary>
    ///     This validator will check that the CSR is issued by a real Yubikey
    /// </summary>
    internal class YubikeyValidator
    {
        private const StringComparison Comparison = StringComparison.InvariantCultureIgnoreCase;

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
            CertificateRequestPolicy policy, YubikeyObject yubikey)
        {
            // If we are already denied for issuance or the policy does not contain any YubikeyPolicy, just continue
            if (result.DeniedForIssuance || !policy.YubikeyPolicy.Any())
            {
                return result;
            }
            // If the Yubikey is not validated, we will not allow it
            if (yubikey.Validated == false)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                LocalizedStrings.YKVal_Invalid_Attestion_with_YubikeyPolicy));
                return result;

            }


            bool foundMatch = false;

            foreach (YubikeyPolicy ykP in policy.YubikeyPolicy)
            {
                //Console.WriteLine(ykP.SaveToString());
                if (this.ObjectMatchesPolicy(ykP, yubikey))
                {
                    if (ykP.Action == YubikeyPolicyAction.Deny)
                    {
                        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                        LocalizedStrings.YKVal_Policy_Matches_with_Reject, ykP.SaveToString()));
                        break;
                    }
                    foundMatch = true;
                    break;
                }
            }

            // if non of the pin policies match, we will deny the request, not matching allowed = deny
            if (foundMatch == false)
            {
                // If all policies are deny policies, then if none match, we will allow the request
                if (policy.YubikeyPolicy.Count(p => p.Action == YubikeyPolicyAction.Deny) != policy.YubikeyPolicy.Count)
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                    LocalizedStrings.YKVal_No_Matching_Policy_Found));
                }
            }
            return result;
        }
        public CertificateRequestValidationResult ExtractAttestion(CertificateRequestValidationResult result,
            CertificateRequestPolicy policy, CertificateDatabaseRow dbRow, out YubikeyObject yubikey)
        {
            if (result.DeniedForIssuance)
            {
                yubikey = new YubikeyObject();
                return result;
            }

            // Yubikey Attestation is stored in these two extensions in the CSR. If present , extract them, otherwise buuild an empty YubikeyObject.
            if (dbRow.CertificateExtensions.ContainsKey(YubikeyX509Extensions.ATTESTION_DEVICE) && dbRow.CertificateExtensions.ContainsKey(YubikeyX509Extensions.ATTESTION_INTERMEDIATE))
            {
                try
                {
                    dbRow.CertificateExtensions.TryGetValue(YubikeyX509Extensions.ATTESTION_DEVICE, out var AttestionCertificateByte);
                    dbRow.CertificateExtensions.TryGetValue(YubikeyX509Extensions.ATTESTION_INTERMEDIATE, out var IntermediateCertificateByte);
                    X509Certificate2 AttestationCertificate = new X509Certificate2(AttestionCertificateByte);
                    X509Certificate2 IntermediateCertificate = new X509Certificate2(IntermediateCertificateByte);
                    yubikey = new YubikeyObject(dbRow.PublicKey, AttestationCertificate, IntermediateCertificate, dbRow.KeyAlgorithm, dbRow.KeyLength);
                }
                catch (Exception ex)
                {
                    yubikey = new YubikeyObject();
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(LocalizedStrings.YKVal_Unable_to_read_embedded_certificates, ex.Message));
                }
            }
            else
            {
                yubikey = new YubikeyObject();
            }
            return result;
        }
        private bool ObjectMatchesPolicy(YubikeyPolicy policy, YubikeyObject yubikey)
        {
            #region Firmware Version
            if (!(policy.MinimumFirmwareString is null) && ! (new Version(policy.MinimumFirmwareString) <= yubikey.FirmwareVersion))
            {
                return false;
            }
            if (!(policy.MaximumFirmwareString is null) && ! (new Version(policy.MaximumFirmwareString) >= yubikey.FirmwareVersion))
            {
                return false;
            }
            #endregion

            #region PIN Policy
            if (policy.PinPolicies.Any() && ! policy.PinPolicies.Contains(yubikey.PinPolicy))
            {
                return false;
            }
            #endregion

            #region Touch Policy
            if (policy.TouchPolicies.Any() && !policy.TouchPolicies.Contains(yubikey.TouchPolicy))
            {
                return false;
            }
            #endregion

            #region Form Factor
            if (policy.Formfactor.Any() && !policy.Formfactor.Contains(yubikey.FormFactor))
            {
                return false;
            }
            #endregion

            if (policy.KeyAlgorithmFamilies.Any() && ! policy.KeyAlgorithmFamilies.Contains(yubikey.keyAlgorithm))
            {
                return false;
            }

            if (policy.Edition.Any() && ! policy.Edition.Contains(yubikey.Edition))
            {
                return false;
            }

            return true;
        }
    }
}