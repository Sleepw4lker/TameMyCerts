// Copyright 2021-2024 Uwe Gradenegger <uwe@gradenegger.eu>
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
        private CertificateRequest _CertificateRequest;

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
            CertificateRequestPolicy policy, YubikeyObject yubikey)
        {
            if (result.DeniedForIssuance || null == policy.YubikeyPolicy)
            {
                return result;
            }


            #region PIN Policy
            if (policy.YubikeyPolicy.DisallowedPinPolicies.Any())
            {
                foreach (var PinPolicy in policy.YubikeyPolicy.DisallowedPinPolicies.Where(s => s.Equals(yubikey.PinPolicy, Comparison)))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                    LocalizedStrings.YKVal_Disallowed_PIN_Policy, yubikey.PinPolicy));
                }
            }
            if (policy.YubikeyPolicy.AllowedPinPolicies.Any())
            {
                if (!(policy.YubikeyPolicy.AllowedPinPolicies.Contains(yubikey.PinPolicy)))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                    LocalizedStrings.YKVal_Allowed_PIN_Policy, yubikey.PinPolicy));
                }
            }
            #endregion

            #region Touch Policy
            if (policy.YubikeyPolicy.DisallowedTouchPolicies.Any())
            {
                foreach (var TouchPolicy in policy.YubikeyPolicy.DisallowedTouchPolicies.Where(s => s.Equals(yubikey.TouchPolicy, Comparison)))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                    LocalizedStrings.YKVal_Disallowed_Touch_Policy, yubikey.TouchPolicy));
                }
            }
            if (policy.YubikeyPolicy.AllowedTouchPolicies.Any())
            {
                if (!(policy.YubikeyPolicy.AllowedTouchPolicies.Contains(yubikey.TouchPolicy)))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                    LocalizedStrings.YKVal_Allowed_Touch_Policy, yubikey.TouchPolicy));
                }
            }
            #endregion

            #region Firmware Version
            // Check if the firmware version is allowed
            if (policy.YubikeyPolicy.DisallowedFirmwareVersion.Any())
            {
                foreach (var FirmwareVersion in policy.YubikeyPolicy.DisallowedFirmwareVersion.Where(s => s.Equals(yubikey.FirmwareVersion.ToString(), Comparison)))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                    LocalizedStrings.YKVal_Disallowed_Firmware_Version, yubikey.FirmwareVersion.ToString()));
                }
            }
            if (policy.YubikeyPolicy.AllowedFirmwareVersion.Any())
            {
                if (!(policy.YubikeyPolicy.AllowedFirmwareVersion.Contains(yubikey.FirmwareVersion.ToString())))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                    LocalizedStrings.YKVal_Allowed_Firmware_Version, yubikey.FirmwareVersion.ToString()));
                }
            }
            #endregion

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
            if (dbRow.CertificateExtensions.ContainsKey(YubikeyOID.ATTESTION_DEVICE) && dbRow.CertificateExtensions.ContainsKey(YubikeyOID.ATTESTION_INTERMEDIATE))
            {
                try
                {
                    dbRow.CertificateExtensions.TryGetValue(YubikeyOID.ATTESTION_DEVICE, out var AttestionCertificateByte);
                    dbRow.CertificateExtensions.TryGetValue(YubikeyOID.ATTESTION_INTERMEDIATE, out var IntermediateCertificateByte);
                    X509Certificate2 AttestationCertificate = new X509Certificate2(AttestionCertificateByte);
                    X509Certificate2 IntermediateCertificate = new X509Certificate2(IntermediateCertificateByte);
                    yubikey = new YubikeyObject(dbRow.PublicKey, AttestationCertificate, IntermediateCertificate);
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
    }
}