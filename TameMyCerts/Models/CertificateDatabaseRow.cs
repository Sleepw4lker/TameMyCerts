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
using System.Linq;
using System.Runtime.InteropServices;
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
        RawName = serverPolicy.GetBinaryRequestPropertyOrDefault("Request.RawName");
        RequestID = serverPolicy.GetLongRequestPropertyOrDefault("RequestID");
        RequesterName = serverPolicy.GetStringRequestPropertyOrDefault("RequesterName");
        RequestType = serverPolicy.GetLongRequestPropertyOrDefault("RequestType") ^ CertCli.CR_IN_FULLRESPONSE;
        Upn = serverPolicy.GetStringCertificatePropertyOrDefault("UPN") ?? string.Empty;
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
        Dictionary<string, string> requestAttributes = null, int requestId = 0)
    {
        NotBefore = DateTimeOffset.Now;
        NotAfter = DateTimeOffset.Now.AddYears(1);

        IX509CertificateRequestPkcs10 certificateRequestPkcs10 = new CX509CertificateRequestPkcs10();

        try
        {
            if (certificateRequestPkcs10.TryInitializeFromInnerRequest(request, requestType))
            {
                CertificateExtensions = certificateRequestPkcs10.GetRequestExtensions();
                KeyAlgorithm = certificateRequestPkcs10.GetKeyAlgorithm();
                KeyLength = certificateRequestPkcs10.PublicKey.Length;
                RawName = Convert.FromBase64String(certificateRequestPkcs10.Subject.EncodedName);
                SubjectRelativeDistinguishedNames = InlineSubjectRelativeDistinguishedNames;
                SubjectAlternativeNameExtension = GetSubjectAlternativeNameExtension();
                PublicKey = Convert.FromBase64String(certificateRequestPkcs10.PublicKey.EncodedKey);
                RawRequest = Convert.FromBase64String(certificateRequestPkcs10.get_RawData());
                RequestType = CertCli.CR_IN_PKCS10;
            }
        }
        finally
        {
            ReleaseComObject(ref certificateRequestPkcs10);
        }

        // We must ensure string comparison against request attributes will be processed case-insensitive
        RequestAttributes = requestAttributes != null
            ? new Dictionary<string, string>(
                requestAttributes.Where(kvp => !string.IsNullOrEmpty(kvp.Key)),
                StringComparer.InvariantCultureIgnoreCase)
            : new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

        RequestID = requestId;
    }

    /// <summary>
    ///     The NotBefore Date as read from the CA database record.
    /// </summary>
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
    ///     The internal RequestID.
    /// </summary>
    public int RequestID { get; }

    /// <summary>
    ///     The requester name.
    /// </summary>
    public string RequesterName { get; }

    /// <summary>
    ///     The request type as defined in certcli.h (PKCS#10, PKCS#7 or CMS).
    /// </summary>
    public int RequestType { get; }

    /// <summary>
    ///     The UPN database column. Contains the UPN of the requesting user or machine.
    /// </summary>
    public string Upn { get; } = string.Empty;

    /// <summary>
    ///     The identifier for the certificate template used. V1 templates are identified by their name, V2 and higher
    ///     templates are identified by their OID.
    /// </summary>
    public string CertificateTemplate { get; }

    /// <summary>
    ///     Raw binary public key as read from the certificate request.
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    ///     Raw binary Subject Distinguished Name as read from the certificate request.
    /// </summary>
    public byte[] RawName { get; }

    /// <summary>
    ///     Inline request attributes (like process name). These are read on-demand from the inline certificate request. There
    ///     are rare cases in which it is not possible to parse the inline request. The property returns an empty collection in
    ///     this case.
    /// </summary>
    public Dictionary<string, string> InlineRequestAttributes
    {
        get
        {
            IX509CertificateRequestPkcs10 certificateRequestPkcs10 = new CX509CertificateRequestPkcs10();

            var attributeList = new Dictionary<string, string>();

            try
            {
                if (certificateRequestPkcs10.TryInitializeFromInnerRequest(
                        Convert.ToBase64String(RawRequest), RequestType))
                {
                    attributeList = certificateRequestPkcs10.GetInlineRequestAttributeList();
                }
            }
            finally
            {
                ReleaseComObject(ref certificateRequestPkcs10);
            }

            return attributeList;
        }
    }

    /// <summary>
    ///     The Subject RDNs taken from the inline certificate request, which may become useful when requesting custom RDNs.
    /// </summary>
    public List<KeyValuePair<string, string>> InlineSubjectRelativeDistinguishedNames =>
        X509DistinguishedNameParser.Parse(RawName);

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
        return oid switch
        {
            WinCrypt.szOID_RSA_RSA => KeyAlgorithmFamily.RSA,
            WinCrypt.szOID_X957_DSA => KeyAlgorithmFamily.DSA,
            WinCrypt.szOID_ECC_PUBLIC_KEY => KeyAlgorithmFamily.ECC,
            _ => KeyAlgorithmFamily.UNKNOWN
        };
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
            throw new Exception("Unable to parse the Subject Alternative Name certificate request extension.");
        }
    }

    private static void ReleaseComObject<T>(ref T comObj)
    {
        if (comObj is null)
        {
            return;
        }

        Marshal.ReleaseComObject(comObj);
        comObj = default;
    }
}