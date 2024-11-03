// Copyright 2021-2024 Uwe Gradenegger <uwe@gradenegger.eu>

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
using System.Runtime.InteropServices;
using System.Text;
using CERTCLILib;
using CERTENROLLLib;
using TameMyCerts.ClassExtensions;
using TameMyCerts.Enums;
using TameMyCerts.X509;

namespace TameMyCerts.Models;

internal class CertificateDatabaseRow
{
    public CertificateDatabaseRow(CCertServerPolicy serverPolicy)
    {
        NotBefore = serverPolicy.GetDateCertificatePropertyOrDefault("NotBefore");
        NotAfter = serverPolicy.GetDateCertificatePropertyOrDefault("NotAfter");
        KeyLength = serverPolicy.GetLongCertificatePropertyOrDefault("PublicKeyLength");
        PublicKey = serverPolicy.GetBinaryCertificatePropertyOrDefault("RawPublicKey");
        RawRequest = serverPolicy.GetBinaryRequestPropertyOrDefault("RawRequest");
        RequestType = serverPolicy.GetLongRequestPropertyOrDefault("RequestType") ^ CertCli.CR_IN_FULLRESPONSE;
        Upn = serverPolicy.GetStringCertificatePropertyOrDefault("UPN") ?? string.Empty;
        DistinguishedName = serverPolicy.GetStringRequestPropertyOrDefault("Request.DistinguishedName") ??
                            string.Empty;
        CertificateTemplate = serverPolicy.GetStringCertificatePropertyOrDefault("CertificateTemplate");

        RequestAttributes = serverPolicy.GetRequestAttributes();
        CertificateExtensions = serverPolicy.GetCertificateExtensions();
        KeyAlgorithm =
            GetKeyAlgorithmFamily(serverPolicy.GetStringCertificatePropertyOrDefault("PublicKeyAlgorithm"));
        SubjectRelativeDistinguishedNames = serverPolicy.GetSubjectRelativeDistinguishedNames();
        SubjectAlternativeNameExtension = GetSubjectAlternativeNameExtension();
    }
  
    // To inject unit tests
    public CertificateDatabaseRow(string request, int requestType,
        Dictionary<string, string> requestAttributes = null)
    {
        NotBefore = DateTimeOffset.Now;
        NotAfter = DateTimeOffset.Now.AddYears(1);

        var certificateRequestPkcs10 = new CX509CertificateRequestPkcs10();

        if (certificateRequestPkcs10.TryInitializeFromInnerRequest(request, requestType))
        {
            CertificateExtensions = certificateRequestPkcs10.GetRequestExtensions();
            KeyAlgorithm = certificateRequestPkcs10.GetKeyAlgorithm();
            KeyLength = certificateRequestPkcs10.PublicKey.Length;
            DistinguishedName = certificateRequestPkcs10.GetSubjectDistinguishedName();
            SubjectRelativeDistinguishedNames = DistinguishedName.Equals(string.Empty)
                ? new List<KeyValuePair<string, string>>()
                : GetDnComponents(DistinguishedName);
            SubjectAlternativeNameExtension = GetSubjectAlternativeNameExtension();
            PublicKey = Convert.FromBase64String(certificateRequestPkcs10.PublicKey.EncodedKey);
            RawRequest = Convert.FromBase64String(certificateRequestPkcs10.get_RawData());
            RequestType = CertCli.CR_IN_PKCS10;
        }

        Marshal.ReleaseComObject(certificateRequestPkcs10);

        // This is to ensure string comparison against request attributes will be processed case-insensitive
        RequestAttributes = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

        if (requestAttributes != null)
        {
            foreach (var keyValuePair in requestAttributes.Where(keyValuePair =>
                         !RequestAttributes.ContainsKey(keyValuePair.Key)))
            {
                RequestAttributes.Add(keyValuePair.Key, keyValuePair.Value);
            }
        }
    }

    public DateTimeOffset NotBefore { get; }

    /// <summary>
    ///     The NotAfter Date as read from the CA database record.
    /// </summary>
    public DateTimeOffset NotAfter { get; }

    /// <summary>
    ///     A list of request attributes as read from the CA database record.
    /// </summary>
    public Dictionary<string, string> RequestAttributes { get; }

    /// <summary>
    ///     The X.509 certificate extensions before TameMyCerts has processed the certificate request (as they come from the
    ///     Windows Default policy module)
    /// </summary>
    public Dictionary<string, byte[]> CertificateExtensions { get; }

    public KeyAlgorithmFamily KeyAlgorithm { get; }

    /// <summary>
    ///     A list of all Subject Relative Distinguished names in the certificate request. Can either be populated from the
    ///     data read from the CA database record or parsed from an actual certificate request.
    /// </summary>
    public List<KeyValuePair<string, string>> SubjectRelativeDistinguishedNames { get; }

    public List<KeyValuePair<string, string>> SubjectAlternativeNames =>
        SubjectAlternativeNameExtension.AlternativeNames;

    public int KeyLength { get; }

    /// <summary>
    ///     The Subject Alternative Name certificate extension class. It allows to inspect or add or remove entries during
    ///     processing. Only available if the Initialize method has been called before.
    /// </summary>
    public X509CertificateExtensionSubjectAlternativeName SubjectAlternativeNameExtension { get; }

    /// <summary>
    ///     The raw certificate request in binary form.
    /// </summary>
    public byte[] RawRequest { get; }

    /// <summary>
    ///     The request type as defined in certcli.h (PKCS#10, PKCS#7 or CMS).
    /// </summary>
    public int RequestType { get; }

    /// <summary>
    ///     The UPN database column. Contains the UPN of the requesting user or machine.
    /// </summary>
    public string Upn { get; } = string.Empty;

    /// <summary>
    ///     The Subject Distinguished name as comma-separated string.
    /// </summary>
    public string DistinguishedName { get; }

    /// <summary>
    ///     The identifier for the certificate template used. V1 templates are identified by their name, V2 and higher
    ///     templates are identified by their OID.
    /// </summary>
    public string CertificateTemplate { get; }
  
    /// <summary>
    ///     Inline request attributes (like process name). These are read on-demand from the inline certificate request. There
    ///     are rare cases in which it is not possible to parse the inline request. The property returns an empty collection in
    ///     this case.
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    ///     Inline request attributes (like process name). These are read on-demand from the inline certificate request. There
    ///     are rare cases in which it is not possible to parse the inline request. The property returns an empty collection in
    ///     this case.
    /// </summary>
    public Dictionary<string, string> InlineRequestAttributes
    {
        get
        {
            // Early binding would raise an E_NOINTERFACE exception on Windows 2012 R2 and earlier
            var certificateRequestPkcs10 =
                (IX509CertificateRequestPkcs10)Activator.CreateInstance(
                    Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));

            var attributeList = new Dictionary<string, string>();

            if (certificateRequestPkcs10.TryInitializeFromInnerRequest(
                    Convert.ToBase64String(RawRequest), RequestType))
            {
                attributeList = certificateRequestPkcs10.GetInlineRequestAttributeList();
            }

            Marshal.ReleaseComObject(certificateRequestPkcs10);

            return attributeList;
        }
    }

    /// <summary>
    ///     The Subject RDNs taken from the inline certificate request, which may become useful when requesting custom RDNs.
    /// </summary>
    public List<KeyValuePair<string, string>> InlineSubjectRelativeDistinguishedNames =>
        DistinguishedName.Equals(string.Empty)
            ? new List<KeyValuePair<string, string>>()
            : GetDnComponents(DistinguishedName);

    /// <summary>
    ///     A list of all identities contained in the certificate request (containing Subject and SAN). In case of an online
    ///     template, this returns only the UPN or dNSName of the requesting entity.
    /// </summary>
    /// <param name="isOffline"></param>
    /// <param name="isUserScope"></param>
    /// <returns></returns>
    public List<KeyValuePair<string, string>> GetIdentities(bool isOffline = false, bool isUserScope = false)
    {
        var result = new List<KeyValuePair<string, string>>();

        if (isOffline)
        {
            result.AddRange(SubjectRelativeDistinguishedNames);
            result.AddRange(SubjectAlternativeNames);
        }
        else
        {
            result.Add(isUserScope
                ? new KeyValuePair<string, string>("userPrincipalName", Upn)
                : new KeyValuePair<string, string>("dNSName", Upn.Replace("$@", ".")));
        }

        return result;
    }

    private static KeyAlgorithmFamily GetKeyAlgorithmFamily(string oid)
    {
        switch (oid)
        {
            case WinCrypt.szOID_RSA_RSA:
                return KeyAlgorithmFamily.RSA;

            case WinCrypt.szOID_X957_DSA:
                return KeyAlgorithmFamily.DSA;

            case WinCrypt.szOID_ECC_PUBLIC_KEY:
                return KeyAlgorithmFamily.ECC;

            default:
                return KeyAlgorithmFamily.UNKNOWN;
        }
    }

    private X509CertificateExtensionSubjectAlternativeName GetSubjectAlternativeNameExtension()
    {
        if (!CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2))
        {
            return new X509CertificateExtensionSubjectAlternativeName();
        }

        try
        {
            return new X509CertificateExtensionSubjectAlternativeName(
                CertificateExtensions.First(x => x.Key.Equals(WinCrypt.szOID_SUBJECT_ALT_NAME2)).Value);
        }
        catch
        {
            throw new Exception(LocalizedStrings.ReqVal_Err_Parse_San);
        }
    }

    private static string SubstituteRdnTypeAliases(string rdnType)
    {
        // Convert all known aliases used by the Microsoft API to the "official" name as specified in ITU-T X.520 and/or RFC 4519
        // https://www.itu.int/itu-t/recommendations/rec.aspx?rec=X.520
        // https://datatracker.ietf.org/doc/html/rfc4519#section-2

        // Here are some sources the used list is based on
        // https://www.gradenegger.eu/?p=2717
        // https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certstrtonamea
        // https://docs.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-osco/dbdc3411-ed0a-4713-a01b-1ae0da5e75d4

        var key = rdnType.ToUpperInvariant();

        return RdnTypes.ShortToLongName.TryGetValue(key, out var value)
            ? value
            : rdnType;
    }

    // If the Subject RDN contains quotes or special characters, the IX509CertificateRequest interface escapes these with quotes
    // As this messes up our comparison logic, we must remove the additional quotes
    private static string RemoveQuotesFromSubjectRdn(string rdn)
    {
        if (rdn.Length == 0)
        {
            return rdn;
        }

        // Not in quotes, nothing to do
        if (rdn[0] != '"' && rdn[rdn.Length - 1] != '"')
        {
            return rdn;
        }

        // Skip first and last char, then remove every 2nd quote

        const char quoteChar = '\"';
        var inQuotedString = false;
        var stringBuilder = new StringBuilder();

        for (var i = 1; i < rdn.Length - 1; i++)
        {
            var currentChar = rdn[i];

            if (currentChar == quoteChar)
            {
                if (!inQuotedString)
                {
                    stringBuilder.Append(currentChar);
                }

                inQuotedString = !inQuotedString;
            }
            else
            {
                stringBuilder.Append(currentChar);
            }
        }

        return stringBuilder.ToString();
    }

    private static List<KeyValuePair<string, string>> GetDnComponents(string distinguishedName)
    {
        // Licensed to the .NET Foundation under one or more agreements.
        // The .NET Foundation licenses this file to you under the MIT license.

        // https://github.com/dotnet/corefx/blob/c539d6c627b169d45f0b4cf1826b560cd0862abe/src/System.DirectoryServices/src/System/DirectoryServices/ActiveDirectory/Utils.cs#L440-L449

        var components = SplitSubjectDn(distinguishedName, ',');
        var dnComponents = new List<KeyValuePair<string, string>>();

        if (components.Length == 0)
        {
            return dnComponents;
        }

        for (var i = 0; i < components.GetLength(0); i++)
        {
            var subComponents = SplitSubjectDn(components[i], '=');

            if (subComponents.GetLength(0) != 2)
            {
                throw new ArgumentException();
            }

            var key = SubstituteRdnTypeAliases(subComponents[0].Trim());
            var value = RemoveQuotesFromSubjectRdn(subComponents[1].Trim());

            if (key.Length > 0)
            {
                dnComponents.Add(new KeyValuePair<string, string>(key, value));
            }
            else
            {
                throw new ArgumentException();
            }
        }

        return dnComponents;
    }

    private static string[] SplitSubjectDn(string distinguishedName, char delimiter)
    {
        // Licensed to the .NET Foundation under one or more agreements.
        // The .NET Foundation licenses this file to you under the MIT license.

        // https://github.com/dotnet/corefx/blob/c539d6c627b169d45f0b4cf1826b560cd0862abe/src/System.DirectoryServices/src/System/DirectoryServices/ActiveDirectory/Utils.cs#L440-L449

        var resultList = new List<string>();

        if (string.IsNullOrEmpty(distinguishedName))
        {
            return resultList.ToArray();
        }

        var inQuotedString = false;
        const char quoteChar = '\"';
        const char escapeChar = '\\';
        var nextTokenStart = 0;

        for (var i = 0; i < distinguishedName.Length; i++)
        {
            var currentChar = distinguishedName[i];

            switch (currentChar)
            {
                case quoteChar:

                    inQuotedString = !inQuotedString;

                    break;

                case escapeChar:

                    if (i < distinguishedName.Length - 1)
                    {
                        i++;
                    }

                    break;
            }

            if (!inQuotedString && currentChar == delimiter)
            {
                // we found an unquoted character that matches the delimiter
                // split it at the delimiter (add the token that ends at this delimiter)
                resultList.Add(distinguishedName.Substring(nextTokenStart, i - nextTokenStart));
                nextTokenStart = i + 1;
            }

            if (i != distinguishedName.Length - 1)
            {
                continue;
            }

            // we've reached the end 

            // if we are still in quoted string, the format is invalid
            if (inQuotedString)
            {
                throw new ArgumentException();
            }

            // we need to end the last token
            resultList.Add(distinguishedName.Substring(nextTokenStart, i - nextTokenStart + 1));
        }

        return resultList.ToArray();
    }
}