using System;
using System.Collections.Generic;
using System.Globalization;

namespace TameMyCerts
{
    // TODO: can we refactor this so that methods are hidden or readonly to the Policy class
    public class CertificateRequestValidationResult
    {
        public CertificateRequestValidationResult(bool auditOnly = false)
        {
            AuditOnly = auditOnly;
        }

        public DateTimeOffset NotAfter { get; set; } = DateTimeOffset.MinValue;
        public int StatusCode { get; set; } = WinError.ERROR_SUCCESS;
        public bool DeniedForIssuance { get; set; }
        public bool AuditOnly { get; }
        public List<string> Description { get; set; } = new List<string>();

        public void SetFailureStatus()
        {
            DeniedForIssuance = true;
            StatusCode = StatusCode == 0 ? WinError.NTE_FAIL : StatusCode;
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

        public void SetNotAfter(string desiredNotAfter)
        {
            if (desiredNotAfter == null)
            {
                return;
            }

            // The "o" standard format specifier corresponds to the "yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fffffffzzz" custom format string for DateTimeOffset values.
            if (DateTimeOffset.TryParseExact(desiredNotAfter, "o", CultureInfo.InvariantCulture.DateTimeFormat,
                    DateTimeStyles.AssumeUniversal, out var notAfter))
            {
                if (notAfter < DateTimeOffset.UtcNow)
                {
                    SetFailureStatus(string.Format(LocalizedStrings.ReqVal_Err_NotAfter_Passed,
                        notAfter.UtcDateTime));
                }
                else
                {
                    NotAfter = notAfter;
                }
            }
            else
            {
                SetFailureStatus(LocalizedStrings.ReqVal_Err_NotAfter_Invalid);
            }
        }
    }
}