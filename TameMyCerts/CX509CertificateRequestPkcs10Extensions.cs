// Copyright 2021 Uwe Gradenegger

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

namespace TameMyCerts
{
    public static class CX509CertificateRequestPkcs10Extensions
    {
        public static bool TryInitializeFromInnerRequest(this IX509CertificateRequestPkcs10 certificateRequestPkcs10, string certificateRequest, int requestType)
        {
            switch (requestType)
            {
                case CertCli.CR_IN_CMC:

                    var certificateRequestCmc =
                        (IX509CertificateRequestCmc)Activator.CreateInstance(
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
                        (IX509CertificateRequestPkcs7)Activator.CreateInstance(
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
                    return LocalizedStrings.Unknown;
            }
        }

        public static Dictionary<string, string> GetInlineRequestAttributeList(
            this IX509CertificateRequestPkcs10 certificateRequestPkcs10)
        {
            var attributeList = new Dictionary<string, string>();

            for (var i = 0; i < certificateRequestPkcs10.CryptAttributes.Count; i++)
            {
                var cryptAttribute = certificateRequestPkcs10.CryptAttributes[i];
                string rawData;
                try
                {
                    rawData = cryptAttribute.Values[0].get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64);
                }
                catch
                {
                    continue;
                }

                if (cryptAttribute.ObjectId.Value == WinCrypt.szOID_REQUEST_CLIENT_INFO)
                {
                    var clientId = new CX509AttributeClientId();

                    try
                    {
                        clientId.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64, rawData);

                        attributeList.Add("processName", clientId.ProcessName.ToLowerInvariant());
                        attributeList.Add("machineDnsName", clientId.MachineDnsName);
                    }
                    catch
                    {
                        // continue silently
                    }
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
                // Will throw an exception if empty
                subjectDn = certificateRequestPkcs10.Subject.Name;
            }
            catch
            {
                // Subject DN is empty, we're done
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

        public static bool TryGetSubjectAlternativeNameList(this IX509CertificateRequestPkcs10 certificateRequestPkcs10,
            out List<KeyValuePair<string, string>> subjectAltNameList)
        {
            subjectAltNameList = new List<KeyValuePair<string, string>>();

            int index;

            try
            {
                var oid = new CObjectId();
                oid.InitializeFromValue(WinCrypt.szOID_SUBJECT_ALT_NAME2);
                index = certificateRequestPkcs10.X509Extensions.get_IndexByObjectId(oid);
            }
            catch
            {
                // No SAN extension, we're done
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

                            var ipAddress =
                                new IPAddress(
                                    Convert.FromBase64String(san.get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64)));
                            subjectAltNameList.Add(new KeyValuePair<string, string>("iPAddress", ipAddress.ToString()));

                            break;

                        default:

                            return false;
                    }
                }
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool HasForbiddenExtensions(this IX509CertificateRequestPkcs10 certificateRequestPkcs10)
        {
            foreach (IX509Extension extension in certificateRequestPkcs10.X509Extensions)
            {
                switch (extension.ObjectId.Value)
                {
                    // The subject directory attributes extension can be used to convey identification attributes such as the nationality of the certificate subject.
                    // The extension value is a sequence of OID-value pairs.
                    case WinCrypt.szOID_SUBJECT_DIR_ATTRS: return true;

                    // KB5014754. Validation logic is yet to be established.
                    case WinCrypt.szOID_DS_CA_SECURITY_EXT: return true;
                }
            }

            return false;
        }

        private static string SubstituteRdnTypeAliases(string rdnType)
        {
            // Convert all known aliases used by the Microsoft API to the "official" name as specified in ITU-T X.520 and/or RFC 4519
            // https://www.itu.int/itu-t/recommendations/rec.aspx?rec=X.520
            // https://datatracker.ietf.org/doc/html/rfc4519#section-2

            // Here are some sources the below list is based on
            // https://www.gradenegger.eu/?p=2717
            // https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certstrtonamea
            // https://docs.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-osco/dbdc3411-ed0a-4713-a01b-1ae0da5e75d4

            switch (rdnType.ToUpperInvariant())
            {
                case "C": return "countryName";
                case "CN": return "commonName";
                case "DC": return "domainComponent";
                case "E": return "emailAddress";
                case "L": return "localityName";
                case "O": return "organizationName";
                case "OU": return "organizationalUnitName";
                case "S": return "stateOrProvinceName";
                case "G": return "givenName";
                case "I": return "initials";
                case "SN": return "surname";
                case "STREET": return "streetAddress";
                case "T": return "title";
                case "UNSTRUCTUREDNAME": return "unstructuredName";
                case "UNSTRUCTUREDADDRESS": return "unstructuredAddress";
                case "DEVICESERIALNUMBER": return "deviceSerialNumber";
                case "POSTALCODE": return "postalCode";
                case "DESCRIPTION": return "description";
                case "POBOX": return "postOfficeBox";
                case "PHONE": return "telephoneNumber";

                default: return rdnType;
            }
        }

        // If the subject RDN contains quotes or special characters, the IX509CertificateRequest interface escapes these with quotes
        // As this messes up our comparison logic, we must remove the additional quotes
        private static string RemoveQuotesFromSubjectRdn(string rdn)
        {
            if (rdn == null)
            {
                return null;
            }

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

            // First split by ','
            var components = SplitSubjectDn(distinguishedName, ',');

            if (components == null)
            {
                return null;
            }

            var dnComponents = new List<KeyValuePair<string, string>>();

            for (var i = 0; i < components.GetLength(0); i++)
            {
                // split each component by '='
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

            if (string.IsNullOrEmpty(distinguishedName))
            {
                return null;
            }

            var inQuotedString = false;
            const char quoteChar = '\"';
            const char escapeChar = '\\';
            var nextTokenStart = 0;
            var resultList = new List<string>();

            // get the actual tokens
            for (var i = 0; i < distinguishedName.Length; i++)
            {
                var currentChar = distinguishedName[i];

                switch (currentChar)
                {
                    case quoteChar:

                        inQuotedString = !inQuotedString;
                        break;

                    case escapeChar:

                        // skip the next character (if one exists)
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

                if (i == distinguishedName.Length - 1)
                {
                    // we've reached the end 

                    // if we are still in quoted string, the format is invalid
                    if (inQuotedString)
                    {
                        throw new ArgumentException();
                    }

                    // we need to end the last token
                    resultList.Add(distinguishedName.Substring(nextTokenStart, i - nextTokenStart + 1));
                }
            }

            return resultList.ToArray();
        }
    }
}