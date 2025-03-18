// Copyright 2021-2025 Uwe Gradenegger <info@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


using System.Linq;
using TameMyCerts.Enums;
using TameMyCerts.Models;

namespace TameMyCerts.Validators;

internal class FinalResultValidator
{
    public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
        CertificateRequestPolicy policy, CertificateDatabaseRow dbRow)
    {
        if (result.DeniedForIssuance)
        {
            return result;
        }

        #region Deny if the final certificate has no identity

        if (!policy.PermitEmptyIdentities &&
            (!dbRow.SubjectRelativeDistinguishedNames.Any(x =>
                 x.Key.Equals(RdnTypes.CommonName) && !x.Value.Equals(string.Empty)) ||
             (policy.ReadSubjectFromRequest && !dbRow.InlineSubjectRelativeDistinguishedNames.Any(x =>
                 x.Key.Equals(RdnTypes.CommonName) && !x.Value.Equals(string.Empty)))) &&
            !result.CertificateProperties.Any(x =>
                x.Key.Equals(RdnTypes.NameProperty[RdnTypes.CommonName]) && !x.Value.Equals(string.Empty)) &&
            dbRow.SubjectAlternativeNameExtension.AlternativeNames.Count.Equals(0) &&
            result.SubjectAlternativeNameExtension.AlternativeNames.Count.Equals(0))
        {
            result.SetFailureStatus(WinError.CERT_E_INVALID_NAME, LocalizedStrings.FinVal_No_Identity);
        }

        #endregion

        return result;
    }
}