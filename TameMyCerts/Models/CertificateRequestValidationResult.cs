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

using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using TameMyCerts.Enums;

namespace TameMyCerts.Models
{
    internal class CertificateRequestValidationResult
    {
        public bool ApplyPolicy = true;
        public DateTimeOffset NotBefore { get; set; }
        public DateTimeOffset NotAfter { get; set; }
        public int StatusCode { get; set; } = WinError.ERROR_SUCCESS;
        public bool DeniedForIssuance { get; set; }
        public bool AuditOnly { get; set; }
        public List<string> Description { get; set; } = new List<string>();
        public List<KeyValuePair<string, string>> Identities { get; set; } = new List<KeyValuePair<string, string>>();
        public Dictionary<string, string> Extensions { get; set; } = new Dictionary<string, string>();
        public List<string> DisabledExtensions { get; set; } = new List<string>();
        public List<string> DisabledProperties { get; set; } = new List<string>();
        public List<KeyValuePair<string, string>> Properties { get; set; } = new List<KeyValuePair<string, string>>();

        public Dictionary<string, string> RequestAttributes { get; set; } = new Dictionary<string, string>(
            StringComparer.InvariantCultureIgnoreCase);

        public Dictionary<string, string> CertificateExtensions { get; set; } = new Dictionary<string, string>(
            StringComparer.InvariantCultureIgnoreCase);

        public List<KeyValuePair<string, string>> SubjectRelativeDistinguishedNames { get; set; } = new List<KeyValuePair<string, string>>();

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

        public void SetNotAfter(string desiredNotAfter)
        {
            if (desiredNotAfter == string.Empty)
            {
                return;
            }

            // The "o" standard format specifier corresponds to the "yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fffffffzzz" custom format string for DateTimeOffset values.
            if (DateTimeOffset.TryParseExact(desiredNotAfter, "o", CultureInfo.InvariantCulture.DateTimeFormat,
                    DateTimeStyles.AssumeUniversal, out var notAfter))
            {
                if (notAfter > DateTimeOffset.UtcNow)
                {
                    if (notAfter <= NotAfter)
                    {
                        NotAfter = notAfter;
                    }
                }
                else
                {
                    SetFailureStatus(WinError.ERROR_INVALID_TIME,
                        string.Format(LocalizedStrings.ReqVal_Err_NotAfter_Passed, notAfter.UtcDateTime));
                }
            }
            else
            {
                SetFailureStatus(WinError.ERROR_INVALID_TIME, LocalizedStrings.ReqVal_Err_NotAfter_Invalid);
            }
        }

        public bool TryGetSubjectAlternativeNameList(
            out List<KeyValuePair<string, string>> subjectAltNameList)
        {
            subjectAltNameList = new List<KeyValuePair<string, string>>();

            if (!CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2))
            {
                // Request doesn't contain a SAN extension, thus we're done
                return true;
            }

            var extensionAlternativeNames = new CX509ExtensionAlternativeNames();

            try
            {
                extensionAlternativeNames.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64,
                    CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2]
                );

                foreach (IAlternativeName san in extensionAlternativeNames.AlternativeNames)
                {
                    switch (san.Type)
                    {
                        case AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME:

                            subjectAltNameList.Add(
                                new KeyValuePair<string, string>("dNSName", san.strValue));
                            break;

                        case AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME:

                            subjectAltNameList.Add(
                                new KeyValuePair<string, string>("rfc822Name", san.strValue));
                            break;

                        case AlternativeNameType.XCN_CERT_ALT_NAME_URL:

                            subjectAltNameList.Add(
                                new KeyValuePair<string, string>("uniformResourceIdentifier",
                                    san.strValue));
                            break;

                        case AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME:

                            subjectAltNameList.Add(
                                new KeyValuePair<string, string>("userPrincipalName",
                                    san.strValue));
                            break;

                        case AlternativeNameType.XCN_CERT_ALT_NAME_IP_ADDRESS:

                            subjectAltNameList.Add(new KeyValuePair<string, string>("iPAddress",
                                new IPAddress(
                                        Convert.FromBase64String(san.get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64)))
                                    .ToString()));
                            break;

                        default:

                            Marshal.ReleaseComObject(san);
                            return false;
                    }

                    Marshal.ReleaseComObject(san);
                }
            }
            catch
            {
                Marshal.ReleaseComObject(extensionAlternativeNames);
                return false;
            }

            Marshal.ReleaseComObject(extensionAlternativeNames);
            return true;
        }
    }
}