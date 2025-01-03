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
using System.Linq;
using System.Text.RegularExpressions;
using TameMyCerts.ClassExtensions;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.X509;

namespace TameMyCerts.Validators;

/// <summary>
///     This validator is for static entries that shall be put into issued certificates.
/// </summary>
internal class CertificateContentValidator
{
    private const StringComparison Comparison = StringComparison.InvariantCultureIgnoreCase;

    private static string ReplaceTokenValues(string input, string identifier,
        IReadOnlyCollection<KeyValuePair<string, string>> list)
    {
        // This extracts all tokens and verifies if the given list contains (=knows) the token
        foreach (Match match in new Regex(@"{" + identifier + ":([\\-a-zA-Z0-9]*?)}").Matches(input))
        {
            var token = match.Groups[1].Value;

            if (!list.Any(x => x.Key.Equals(token, StringComparison.InvariantCultureIgnoreCase)))
            {
                throw new Exception(string.Format(LocalizedStrings.Token_invalid, identifier, token));
            }
        }

        var output = list.Aggregate(input, (current, identity) =>
            current.ReplaceCaseInsensitive($"{{{identifier}:{identity.Key}}}", identity.Value));

        return output;
    }

    public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
        CertificateRequestPolicy policy, CertificateDatabaseRow dbRow, ActiveDirectoryObject dsObject,
        CertificateAuthorityConfiguration caConfig, YubikeyObject yubikeyObject = null)
    {
        if (yubikeyObject == null)
        {
            yubikeyObject = new YubikeyObject();
        }
        if (result.DeniedForIssuance)
        {
            return result;
        }

        #region Process CRL Distribution Points

        if (policy.CrlDistributionPoints.Count > 0)
        {
            var cdpExt = new X509CertificateExtensionCrlDistributionPoint();

            foreach (var crlDistributionPoint in policy.CrlDistributionPoints)
            {
                cdpExt.AddUniformResourceIdentifier(caConfig.ReplaceTokenValues(crlDistributionPoint));
            }

            cdpExt.InitializeEncode(true);

            result.AddCertificateExtension(WinCrypt.szOID_CRL_DIST_POINTS, cdpExt.RawData);
        }

        #endregion

        #region Process Authority Information Access (and OCSP)

        if (policy.AuthorityInformationAccess.Count > 0 ||
            policy.OnlineCertificateStatusProtocol.Count > 0)
        {
            var aiaExt = new X509CertificateExtensionAuthorityInformationAccess();

            foreach (var authorityInformationAccess in policy.AuthorityInformationAccess)
            {
                aiaExt.AddUniformResourceIdentifier(caConfig.ReplaceTokenValues(authorityInformationAccess));
            }

            foreach (var onlineCertificateStatusProtocol in policy.OnlineCertificateStatusProtocol)
            {
                aiaExt.AddUniformResourceIdentifier(caConfig.ReplaceTokenValues(onlineCertificateStatusProtocol),
                    true);
            }

            aiaExt.InitializeEncode(true);

            result.AddCertificateExtension(WinCrypt.szOID_AUTHORITY_INFO_ACCESS, aiaExt.RawData);
        }

        #endregion

        #region Process modification of Subject DN

        foreach (var rule in policy.OutboundSubject)
        {
            if (!rule.Force && RdnTypes.ToList().Contains(rule.Field) &&
                (
                    dbRow.SubjectRelativeDistinguishedNames.Any(x =>
                        x.Key.Equals(rule.Field, Comparison)) ||
                    result.CertificateProperties.Any(x =>
                        x.Key.Equals(RdnTypes.NameProperty[rule.Field], Comparison))
                ))
            {
                continue;
            }

            try
            {
                var value = rule.Value;

                value = ReplaceTokenValues(value, "ad",
                    null != dsObject ? dsObject.Attributes.ToList() : new List<KeyValuePair<string, string>>());
                value = ReplaceTokenValues(value, "yk",
                    null != yubikeyObject ? yubikeyObject.Attributes.ToList() : new List<KeyValuePair<string, string>>());
                value = ReplaceTokenValues(value, "sdn",
                    policy.ReadSubjectFromRequest
                        ? dbRow.InlineSubjectRelativeDistinguishedNames
                        : dbRow.SubjectRelativeDistinguishedNames);
                value = ReplaceTokenValues(value, "san", dbRow.SubjectAlternativeNames);

                result.SetSubjectDistinguishedName(rule.Field, value);
            }
            catch (Exception ex)
            {
                if (rule.Mandatory)
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, ex.Message);
                }
            }
        }

        #endregion

        #region Process modification of Subject Alternative Name

        foreach (var rule in policy.OutboundSubjectAlternativeName)
        {
            // Check if the SAN is already present unless it is forced
            if (!rule.Force && SanTypes.ToList().Contains(rule.Field) &&
                result.SubjectAlternativeNameExtension.AlternativeNames.Any(x =>
                    x.Key.Equals(rule.Field, Comparison)))
            {
                // Log that the SAN is already present and force has not been set.
                string currentValue = result.SubjectAlternativeNameExtension.AlternativeNames.Where(x => x.Key.Equals(rule.Field, Comparison)).Select(x => x.Value).First();
                ETWLogger.Log.CCVal_4651_SAN_Already_Exists(dbRow.RequestID, subjectAltName: rule.Field, currentValue: currentValue, ignoredValue: rule.Value);
                continue;
            }

            try
            {
                var value = rule.Value;

                value = ReplaceTokenValues(value, "ad",
                    null != dsObject ? dsObject.Attributes.ToList() : new List<KeyValuePair<string, string>>());
                value = ReplaceTokenValues(value, "sdn",
                    policy.ReadSubjectFromRequest
                        ? dbRow.InlineSubjectRelativeDistinguishedNames
                        : dbRow.SubjectRelativeDistinguishedNames);
                value = ReplaceTokenValues(value, "san", dbRow.SubjectAlternativeNames);


                result.SubjectAlternativeNameExtension.AddAlternativeName(rule.Field, value, true);

                // Log that we are adding a SAN, only on success
                ETWLogger.Log.CCVal_4652_SAN_Added(dbRow.RequestID, subjectAltName: rule.Field, addedValue: value);
            }
            catch (Exception ex)
            {
                ETWLogger.Log.CCVal_4653_SAN_Failed_to_add(dbRow.RequestID, subjectAltName: rule.Field, rule.Value);

                if (rule.Mandatory)
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, ex.Message);
                }
            }
        }

        #endregion

        return result;
    }
}