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

using System;
using System.Collections.Generic;
using System.Globalization;
using TameMyCerts.Enums;
using TameMyCerts.X509;

namespace TameMyCerts.Models;

/// <summary>
///     This class contains all necessary information that must be tracked during request validation. Imagine it as a batch
///     card. Its content may get modified by the validator classes.
/// </summary>
internal class CertificateRequestValidationResult
{
    private readonly Dictionary<string, byte[]> _certificateExtensions = new();

    public CertificateRequestValidationResult(CertificateDatabaseRow dbRow)
    {
        NotBefore = dbRow.NotBefore;
        NotAfter = dbRow.NotAfter;
        SubjectAlternativeNameExtension = dbRow.SubjectAlternativeNameExtension;
    }

    // TODO: Implement setter method
    /// <summary>
    ///     The NotBefore Date as read from the CA database record. May be modified during inspection.
    /// </summary>
    public DateTimeOffset NotBefore { get; internal set; }

    // TODO: Implement setter method
    /// <summary>
    ///     The NotAfter Date as read from the CA database record. May be modified during inspection.
    /// </summary>
    public DateTimeOffset NotAfter { get; internal set; }

    /// <summary>
    ///     The HResult status code that shall be returned to the certification authority.
    /// </summary>
    public int StatusCode { get; private set; } = WinError.ERROR_SUCCESS;

    /// <summary>
    ///     Determines if the certificate request shall be denied or not. Can be modified with the SetFailureStatus method.
    /// </summary>
    public bool DeniedForIssuance => StatusCode != WinError.ERROR_SUCCESS;

    /// <summary>
    ///     A textual description of the reasons why the certificate request was denied by the validator classes.
    /// </summary>
    public List<string> Description { get; } = new();

    /// <summary>
    ///     A textual description of warnings that occurred during validation.
    /// </summary>
    public List<string> Warnings { get; } = new();

    /// <summary>
    ///     The X.509 certificate extensions that shall be set after TameMyCerts has processed the certificate request
    /// </summary>
    public Dictionary<string, byte[]> CertificateExtensions
    {
        get
        {
            SubjectAlternativeNameExtension.InitializeEncode();

            if (SubjectAlternativeNameExtension.RawData != Array.Empty<byte>())
            {
                AddCertificateExtension(WinCrypt.szOID_SUBJECT_ALT_NAME2, SubjectAlternativeNameExtension.RawData);
            }

            return _certificateExtensions;
        }
    }

    // TODO: Implement setter method
    // TODO: How to ensure uniqueness?
    /// <summary>
    ///     A list of certificate extensions that shall be disabled when TameMyCerts finishes processing.
    /// </summary>
    public List<string> DisabledCertificateExtensions { get; } = new();

    // TODO: Implement setter method
    // TODO: How to ensure uniqueness?
    /// <summary>
    ///     A list of certificate properties that shall be disabled when TameMyCerts finishes processing.
    /// </summary>
    public List<string> DisabledCertificateProperties { get; } = new();

    // TODO: Implement setter method
    // TODO: Why is this not a dictionary?
    /// <summary>
    ///     A list of certificate properties that shall be set after TameMyCerts has processed the certificate request
    /// </summary>
    public Dictionary<string, string> CertificateProperties { get; } = new();

    // TODO: Implement setter method
    /// <summary>
    ///     The Subject Alternative Name certificate extension class. It allows to inspect or add or remove entries.
    /// </summary>
    public X509CertificateExtensionSubjectAlternativeName SubjectAlternativeNameExtension { get; }

    public void SetSubjectDistinguishedName(string key, string value)
    {
        if (!RdnTypes.ToList().Contains(key))
        {
            throw new NotSupportedException(string.Format(LocalizedStrings.Rdn_Invalid_Field, key));
        }

        if (value.Length > RdnTypes.LengthConstraint[key])
        {
            throw new NotSupportedException(string.Format(LocalizedStrings.Rdn_Value_Too_Long, value,
                key, RdnTypes.LengthConstraint[key], value.Length));
        }

        CertificateProperties[RdnTypes.NameProperty[key]] = value;
    }

    public void AddCertificateExtension(string key, byte[] value)
    {
        _certificateExtensions[key] = value;
    }

    public void SetFailureStatus()
    {
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

    public void AddWarning(string description)
    {
        Warnings.Add(description);
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
}