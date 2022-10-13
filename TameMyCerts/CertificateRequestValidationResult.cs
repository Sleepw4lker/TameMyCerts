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
using System.Globalization;

namespace TameMyCerts
{
    public class CertificateRequestValidationResult
    {
        public CertificateRequestValidationResult()
        {
            AuditOnly = false;
        }

        public CertificateRequestValidationResult(bool auditOnly, string notAfter)
        {
            AuditOnly = auditOnly;
            SetNotAfter(notAfter);
        }

        public DateTimeOffset NotAfter { get; set; } = DateTimeOffset.MinValue;
        public int StatusCode { get; set; } = WinError.ERROR_SUCCESS;
        public bool DeniedForIssuance { get; set; }
        public bool AuditOnly { get; }
        public List<string> Description { get; set; } = new List<string>();
        public List<KeyValuePair<string, string>> Identities { get; set; } = new List<KeyValuePair<string, string>>();
        public Dictionary<string, string> Extensions { get; set; } = new Dictionary<string, string>();
        public Dictionary<string, string> Properties { get; set; } = new Dictionary<string, string>();

        public void SetFailureStatus()
        {
            DeniedForIssuance = true;
            StatusCode = StatusCode == WinError.ERROR_SUCCESS ? WinError.NTE_FAIL : StatusCode;
        }

        public void SetFailureStatus(int statusCode)
        {
            SetFailureStatus();
            StatusCode = statusCode;
        }

        public void SetFailureStatus(int statusCode, string description)
        {
            SetFailureStatus(statusCode);
            SetFailureStatus(description);
        }

        public void SetFailureStatus(int statusCode, List<string> descriptionList)
        {
            SetFailureStatus(statusCode);
            SetFailureStatus(descriptionList);
        }

        public void SetFailureStatus(string description)
        {
            SetFailureStatus();
            Description.Add(description);
        }

        public void SetFailureStatus(List<string> descriptionList)
        {
            SetFailureStatus();
            Description.AddRange(descriptionList);
        }

        private void SetNotAfter(string desiredNotAfter)
        {
            if (desiredNotAfter == string.Empty)
            {
                return;
            }

            // The "o" standard format specifier corresponds to the "yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fffffffzzz" custom format string for DateTimeOffset values.
            if (DateTimeOffset.TryParseExact(desiredNotAfter, "o", CultureInfo.InvariantCulture.DateTimeFormat,
                    DateTimeStyles.AssumeUniversal, out var notAfter))
            {
                if (notAfter < DateTimeOffset.UtcNow)
                {
                    SetFailureStatus(WinError.ERROR_INVALID_TIME,
                        string.Format(LocalizedStrings.ReqVal_Err_NotAfter_Passed, notAfter.UtcDateTime));
                }
                else
                {
                    NotAfter = notAfter;
                }
            }
            else
            {
                SetFailureStatus(WinError.ERROR_INVALID_TIME, LocalizedStrings.ReqVal_Err_NotAfter_Invalid);
            }
        }
    }
}