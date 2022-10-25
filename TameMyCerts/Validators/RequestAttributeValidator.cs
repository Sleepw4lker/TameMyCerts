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
using System.Globalization;
using TameMyCerts.Enums;
using TameMyCerts.Models;

namespace TameMyCerts.Validators
{
    internal class RequestAttributeValidator
    {
        private const string DATETIME_RFC2616 = "ddd, d MMM yyyy HH:mm:ss 'GMT'";

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestValidationResult result,
            CertificationAuthorityConfiguration caConfig)
        {
            #region Process insecure flag/attribute combinations

            if (caConfig.EditFlags.HasFlag(EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2) &&
                result.RequestAttributes.ContainsKey("san"))
            {
                result.SetFailureStatus(WinError.NTE_FAIL, LocalizedStrings.AttribVal_Insecure_Flags);
            }

            #endregion

            #region Process custom StartDate attribute

            if (caConfig.EditFlags.HasFlag(EditFlag.EDITF_ATTRIBUTEENDDATE) &&
                result.RequestAttributes.TryGetValue("StartDate", out var startDate))
            {
                if (DateTimeOffset.TryParseExact(startDate, DATETIME_RFC2616,
                        CultureInfo.InvariantCulture.DateTimeFormat,
                        DateTimeStyles.AssumeUniversal, out var requestedStartDate))
                {
                    if (requestedStartDate >= DateTimeOffset.Now && requestedStartDate <= result.NotAfter)
                    {
                        result.NotBefore = requestedStartDate;
                    }
                    else
                    {
                        result.SetFailureStatus(WinError.ERROR_INVALID_TIME,
                            string.Format(LocalizedStrings.AttribVal_Invalid_StartDate, requestedStartDate.UtcDateTime));
                    }
                }
                else
                {
                    result.SetFailureStatus(WinError.ERROR_INVALID_TIME,
                        string.Format(LocalizedStrings.AttibVal_Err_Parse, "StartDate", startDate));
                }
            }

            #endregion

            return result;
        }
    }
}