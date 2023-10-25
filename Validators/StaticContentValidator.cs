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
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.X509;

namespace TameMyCerts.Validators
{
    /// <summary>
    ///     This validator is for static entries that shall be put into issued certificates.
    /// </summary>
    internal class StaticContentValidator
    {
        private const StringComparison Comparison = StringComparison.InvariantCultureIgnoreCase;

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
            CertificateRequestPolicy policy, CertificateDatabaseRow dbRow, CertificateAuthorityConfiguration caConfig)
        {
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

            #region Process static entries for Subject DN

            foreach (var rule in policy.StaticSubject)
            {
                if (!RdnTypes.ToList().Where(x => x != RdnTypes.DomainComponent).Contains(rule.Field))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                        string.Format(LocalizedStrings.StatVal_Rdn_Invalid_Field, rule.Field));
                    continue;
                }

                if (rule.Value.Length > RdnTypes.LengthConstraint[rule.Field])
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                        string.Format(LocalizedStrings.StatVal_Rdn_Value_Too_Long, rule.Value,
                            rule.Field, RdnTypes.LengthConstraint[rule.Field],
                            rule.Value.Length));
                    continue;
                }

                if (!rule.Force && (
                        dbRow.SubjectRelativeDistinguishedNames.Any(x =>
                            x.Key.Equals(rule.Field, Comparison)) ||
                        result.CertificateProperties.Any(x =>
                            x.Key.Equals(RdnTypes.NameProperty[rule.Field], Comparison))
                    ))
                {
                    continue;
                }

                result.CertificateProperties.Add(
                    new KeyValuePair<string, string>(RdnTypes.NameProperty[rule.Field],
                        rule.Value));
            }

            #endregion

            #region Process static entries for Subject Alternative Name

            foreach (var rule in policy.StaticSubjectAlternativeName)
            {
                if (!SanTypes.ToList().Contains(rule.Field))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED,
                        string.Format(LocalizedStrings.StatVal_Rdn_Invalid_Field, rule.Field));
                    continue;
                }

                if (!rule.Force && result.SubjectAlternativeNameExtension.AlternativeNames.Any(x =>
                        x.Key.Equals(rule.Field, Comparison)))
                {
                    continue;
                }

                // TODO: Cause the request to fail if adding the SAN is not possible (TryAdd). Dont forget to update docs as well.
                result.SubjectAlternativeNameExtension.AddAlternativeName(rule.Field,
                    rule.Value);
            }

            #endregion

            return result;
        }
    }
}