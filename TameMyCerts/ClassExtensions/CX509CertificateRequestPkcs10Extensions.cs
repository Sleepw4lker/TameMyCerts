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
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using CERTENROLLLib;
using TameMyCerts.Models;

namespace TameMyCerts.ClassExtensions
{
    internal static class CX509CertificateRequestPkcs10Extensions
    {
        private static readonly Dictionary<string, string> RdnTypeAliasDictionary = new Dictionary<string, string>
        {
            {"C", "countryName"},
            {"CN", "commonName"},
            {"DC", "domainComponent"},
            {"E", "emailAddress"},
            {"L", "localityName"},
            {"O", "organizationName"},
            {"OU", "organizationalUnitName"},
            {"S", "stateOrProvinceName"},
            {"G", "givenName"},
            {"I", "initials"},
            {"SN", "surname"},
            {"STREET", "streetAddress"},
            {"T", "title"},
            {"UNSTRUCTUREDNAME", "unstructuredName"},
            {"UNSTRUCTUREDADDRESS", "unstructuredAddress"},
            {"DEVICESERIALNUMBER", "deviceSerialNumber"},
            {"POSTALCODE", "postalCode"},
            {"DESCRIPTION", "description"},
            {"POBOX", "postOfficeBox"},
            {"PHONE", "telephoneNumber"}
        };

        public static bool TryInitializeFromInnerRequest(this IX509CertificateRequestPkcs10 certificateRequestPkcs10,
            string certificateRequest, int requestType)
        {
            switch (requestType)
            {
                case CertCli.CR_IN_CMC:

                    var certificateRequestCmc =
                        (IX509CertificateRequestCmc) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestCmc"));

                    try
                    {
                        certificateRequestCmc.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        var innerRequest = certificateRequestCmc.GetInnerRequest(InnerRequestLevel.LevelInnermost);
                        certificateRequest = innerRequest.get_RawData();
                    }
                    catch
                    {
                        return false;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certificateRequestCmc);
                    }

                    break;

                case CertCli.CR_IN_PKCS7:

                    var certificateRequestPkcs7 =
                        (IX509CertificateRequestPkcs7) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs7"));

                    try
                    {
                        certificateRequestPkcs7.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        var innerRequest = certificateRequestPkcs7.GetInnerRequest(InnerRequestLevel.LevelInnermost);
                        certificateRequest = innerRequest.get_RawData();
                    }
                    catch
                    {
                        return false;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certificateRequestPkcs7);
                    }

                    break;
            }

            try
            {
                certificateRequestPkcs10.InitializeDecode(
                    certificateRequest,
                    EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                );
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static string GetKeyAlgorithmName(this IX509CertificateRequestPkcs10 certificateRequestPkcs10)
        {
            switch (certificateRequestPkcs10.PublicKey.Algorithm.Value)
            {
                case WinCrypt.szOID_ECC_PUBLIC_KEY:
                    return "ECC";

                case WinCrypt.szOID_RSA_RSA:
                    return "RSA";

                default:
                    return certificateRequestPkcs10.PublicKey.Algorithm.Value;
            }
        }

        public static Dictionary<string, string> GetInlineRequestAttributeList(
            this IX509CertificateRequestPkcs10 certificateRequestPkcs10)
        {
            return GetInlineRequestAttributeList(certificateRequestPkcs10, new Dictionary<string, string>());
        }

        public static Dictionary<string, string> GetInlineRequestAttributeList(
            this IX509CertificateRequestPkcs10 certificateRequestPkcs10, Dictionary<string, string> attributeList)
        {
            for (var i = 0; i < certificateRequestPkcs10.CryptAttributes.Count; i++)
            {
                var cryptAttribute = certificateRequestPkcs10.CryptAttributes[i];

                // Note that there is no need to extract the RequestCSPProvider here as it is automatically added to the extensions table
                if (cryptAttribute.ObjectId.Value != WinCrypt.szOID_REQUEST_CLIENT_INFO)
                {
                    continue;
                }

                string rawData;

                try
                {
                    rawData = cryptAttribute.Values[0].get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64);
                }
                catch
                {
                    continue;
                }

                var clientId = new CX509AttributeClientId();

                try
                {
                    clientId.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64, rawData);

                    attributeList.Add("ProcessName", clientId.ProcessName.ToLowerInvariant());
                    attributeList.Add("MachineDnsName", clientId.MachineDnsName);
                }
                catch
                {
                    // we don't want an exception to be thrown
                }
                finally
                {
                    Marshal.ReleaseComObject(clientId);
                }
            }

            return attributeList;
        }

        public static bool TryGetSubjectRdnList(
            this IX509CertificateRequestPkcs10 certificateRequestPkcs10,
            out List<KeyValuePair<string, string>> subjectRdnList)
        {
            subjectRdnList = new List<KeyValuePair<string, string>>();

            string subjectDn;

            try
            {
                subjectDn = certificateRequestPkcs10.Subject.Name;
            }
            catch
            {
                // Will throw an exception if Subject DN is empty, then we're done
                return true;
            }

            try
            {
                subjectRdnList = GetDnComponents(subjectDn);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool HasExtension(this IX509CertificateRequestPkcs10 certificateRequestPkcs10,
            string extensionOid)
        {
            return certificateRequestPkcs10.HasExtension(extensionOid, out _);
        }

        public static bool HasExtension(this IX509CertificateRequestPkcs10 certificateRequestPkcs10,
            string extensionOid, out int index)
        {
            index = 0;
            var oid = new CObjectId();

            try
            {
                oid.InitializeFromValue(extensionOid);
                index = certificateRequestPkcs10.X509Extensions.get_IndexByObjectId(oid);
            }
            catch
            {
                return false;
            }
            finally
            {
                Marshal.ReleaseComObject(oid);
            }

            return true;
        }

        public static bool TryGetSubjectAlternativeNameList(this IX509CertificateRequestPkcs10 certificateRequestPkcs10,
            out List<KeyValuePair<string, string>> subjectAltNameList)
        {
            subjectAltNameList = new List<KeyValuePair<string, string>>();

            if (!certificateRequestPkcs10.HasExtension(WinCrypt.szOID_SUBJECT_ALT_NAME2, out var index))
            {
                // Request doesn't contain a SAN extension, thus we're done
                return true;
            }

            var extension = certificateRequestPkcs10.X509Extensions[index];

            var extensionAlternativeNames = new CX509ExtensionAlternativeNames();

            try
            {
                extensionAlternativeNames.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64,
                    extension.get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64)
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

            return RdnTypeAliasDictionary.ContainsKey(key)
                ? RdnTypeAliasDictionary[key]
                : rdnType;
        }

        // If the subject RDN contains quotes or special characters, the IX509CertificateRequest interface escapes these with quotes
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
}