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
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using TameMyCerts.Enums;
using TameMyCerts.Models;

namespace TameMyCerts.Validators;

/// <summary>
///     This validator will check that the CSR is issued by a real Yubikey
/// </summary>
internal class YubikeyValidator
{
    private readonly X509Certificate2Collection _rootCertificates;

    public YubikeyValidator()
    {
        try
        {
            var rootCertificates = new X509Store("YKROOT", StoreLocation.LocalMachine);
            _rootCertificates = rootCertificates.Certificates;
        }
        catch
        {
            _rootCertificates = null;
        }
    }

    public YubikeyValidator(X509Certificate2Collection rootCertificates)
    {
        _rootCertificates = rootCertificates;
    }

    public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
        CertificateRequestPolicy policy, YubikeyObject yubikey, int requestId)
    {
        // If we are already denied for issuance or the policy does not contain any YubikeyPolicy, just continue
        if (result.DeniedForIssuance || !policy.YubikeyPolicy.Any())
        {
            return result;
        }

        // If the Yubikey is not validated, we will not allow it
        if (yubikey.Validated == false)
        {
            ETWLogger.Log.YKVal_4202_Denied_by_Policy(requestId);
            result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                LocalizedStrings.YKVal_Invalid_Attestation_with_YubikeyPolicy));
            return result;
        }

        var foundMatch = false;

        foreach (var ykP in policy.YubikeyPolicy)
        {
            //Console.WriteLine(ykP.SaveToString());
            if (ObjectMatchesPolicy(ykP, yubikey))
            {
                if (ykP.Action == YubikeyPolicyAction.Deny)
                {
                    ETWLogger.Log.YKVal_4201_Denied_by_Policy(requestId, ykP.SaveToString());
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                        LocalizedStrings.YKVal_Policy_Matches_with_Reject, ykP.SaveToString()));
                    return result;
                }

                ETWLogger.Log.YKVal_4204_Matching_policy(requestId, ykP.SaveToString(), yubikey.SaveToString());
                foundMatch = true;

                // Store the AttestationData and Intermediate Certificate in the certificate, if requested
                if (ykP.IncludeAttestationInCertificate)
                {
                    var x509ExtAttestation = new X509Extension(YubikeyX509Extensions.ATTESTATION_DEVICE,
                        yubikey.AttestationCertificate.RawData, false);
                    result.CertificateExtensions.Add(YubikeyX509Extensions.ATTESTATION_DEVICE,
                        x509ExtAttestation.RawData);
                    var x509ExtIntermediate = new X509Extension(YubikeyX509Extensions.ATTESTATION_INTERMEDIATE,
                        yubikey.IntermediateCertificate.RawData, false);
                    result.CertificateExtensions.Add(YubikeyX509Extensions.ATTESTATION_INTERMEDIATE,
                        x509ExtIntermediate.RawData);
                }

                break;
            }

            ETWLogger.Log.YKVal_4206_Debug_failed_to_match_policy(requestId, ykP.SaveToString());
        }

        // If none of the pin policies match, we will deny the request, not matching allowed = deny
        if (foundMatch)
        {
            return result;
        }

        // If all policies are deny policies, then if none match, we will allow the request
        if (policy.YubikeyPolicy.All(p => p.Action != YubikeyPolicyAction.Allow))
        {
            return result;
        }

        ETWLogger.Log.YKVal_4203_Denied_due_to_no_matching_policy_default_deny(requestId);
        result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
            LocalizedStrings.YKVal_No_Matching_Policy_Found));

        return result;
    }

    public CertificateRequestValidationResult ExtractAttestation(CertificateRequestValidationResult result,
        CertificateRequestPolicy policy, CertificateDatabaseRow dbRow, out YubikeyObject yubikey)
    {
        if (result.DeniedForIssuance)
        {
            yubikey = new YubikeyObject();
            return result;
        }

        // Yubikey Attestation is stored in these two extensions in the CSR. If present , extract them, otherwise build an empty YubikeyObject.
        if (dbRow.CertificateExtensions.ContainsKey(YubikeyX509Extensions.ATTESTATION_DEVICE) &&
            dbRow.CertificateExtensions.ContainsKey(YubikeyX509Extensions.ATTESTATION_INTERMEDIATE))
        {
            ETWLogger.Log.YKVal_4209_Found_Attestation_Location(dbRow.RequestID,
                YubikeyX509Extensions.ATTESTATION_DEVICE);
            try
            {
                dbRow.CertificateExtensions.TryGetValue(YubikeyX509Extensions.ATTESTATION_DEVICE,
                    out var attestationCertificateByte);
                dbRow.CertificateExtensions.TryGetValue(YubikeyX509Extensions.ATTESTATION_INTERMEDIATE,
                    out var intermediateCertificateByte);

                yubikey = new YubikeyObject(dbRow.PublicKey, new X509Certificate2(attestationCertificateByte),
                    new X509Certificate2(intermediateCertificateByte), _rootCertificates,
                    dbRow.KeyAlgorithm, dbRow.KeyLength, dbRow.RequestID);
            }
            catch (Exception ex)
            {
                yubikey = new YubikeyObject();
                ETWLogger.Log.YKVal_4205_Failed_to_extract_Yubikey_Attestation(dbRow.RequestID);
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.YKVal_Unable_to_read_embedded_certificates, ex.Message));
            }
        }
        else if (dbRow.CertificateExtensions.ContainsKey(YubikeyX509Extensions.ATTESTATION_DEVICE_PIVTOOL) &&
                 dbRow.CertificateExtensions.ContainsKey(YubikeyX509Extensions.ATTESTATION_INTERMEDIATE))
        {
            ETWLogger.Log.YKVal_4209_Found_Attestation_Location(dbRow.RequestID,
                YubikeyX509Extensions.ATTESTATION_DEVICE_PIVTOOL);
            try
            {
                dbRow.CertificateExtensions.TryGetValue(YubikeyX509Extensions.ATTESTATION_DEVICE_PIVTOOL,
                    out var attestationCertificateByte);
                dbRow.CertificateExtensions.TryGetValue(YubikeyX509Extensions.ATTESTATION_INTERMEDIATE,
                    out var intermediateCertificateByte);

                yubikey = new YubikeyObject(dbRow.PublicKey, new X509Certificate2(attestationCertificateByte),
                    new X509Certificate2(intermediateCertificateByte), _rootCertificates,
                    dbRow.KeyAlgorithm, dbRow.KeyLength, dbRow.RequestID);
            }
            catch (Exception ex)
            {
                yubikey = new YubikeyObject();
                ETWLogger.Log.YKVal_4205_Failed_to_extract_Yubikey_Attestation(dbRow.RequestID);
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                    string.Format(LocalizedStrings.YKVal_Unable_to_read_embedded_certificates, ex.Message));
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

        if (policy.MinimumFirmwareString is not null &&
            !(new Version(policy.MinimumFirmwareString) <= yubikey.FirmwareVersion))
        {
            return false;
        }

        if (policy.MaximumFirmwareString is not null &&
            !(new Version(policy.MaximumFirmwareString) >= yubikey.FirmwareVersion))
        {
            return false;
        }

        #endregion

        #region PIN Policy

        if (policy.PinPolicies.Any() && !policy.PinPolicies.Contains(yubikey.PinPolicy))
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

        #region Slot

        // Look if the slot is in the policy, if not, say that we arent matching
        // Look for both 0xXX and XX
        if (policy.Slot.Any() && !(policy.Slot.Any(s => s.Equals(yubikey.Slot, StringComparison.OrdinalIgnoreCase)) ||
                                   policy.Slot.Any(s =>
                                       s.Equals($"0x{yubikey.Slot}", StringComparison.OrdinalIgnoreCase))))
        {
            return false;
        }

        #endregion

        if (policy.KeyAlgorithmFamilies.Any() && !policy.KeyAlgorithmFamilies.Contains(yubikey.KeyAlgorithm))
        {
            return false;
        }

        if (policy.Edition.Any() && !policy.Edition.Contains(yubikey.Edition))
        {
            return false;
        }

        return true;
    }
}