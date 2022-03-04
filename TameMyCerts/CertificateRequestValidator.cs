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
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using CERTENROLLLib;

namespace TameMyCerts
{
    public class CertificateRequestValidator
    {
        private const string XCN_OID_SUBJECT_ALT_NAME2 = "2.5.29.17";
        private const string XCN_OID_SUBJECT_DIR_ATTRS = "2.5.29.9";
        private const string SZOID_RSA_RSA = "1.2.840.113549.1.1.1";
        private const string SZOID_ECC_PUBLIC_KEY = "1.2.840.10045.2.1";
        private const string SZOID_REQUEST_CLIENT_INFO = "1.3.6.1.4.1.311.21.20";

        public CertificateRequestVerificationResult VerifyRequest(string certificateRequest,
            CertificateRequestPolicy certificateRequestPolicy, CertificateTemplateInfo.Template templateInfo,
            int requestType = CertCli.CR_IN_PKCS10, List<KeyValuePair<string, string>> requestAttributeList = null)
        {
            var result = new CertificateRequestVerificationResult(certificateRequestPolicy.AuditOnly);

            #region Extract and parse request

            switch (requestType)
            {
                case CertCli.CR_IN_CMC:

                    // Short form would raise an E_NOINTERFACE exception on Windows 2012 R2 and earlier
                    var certificateRequestCmc =
                        (IX509CertificateRequestCmc) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestCmc"));

                    // Try to open the Certificate Request
                    try
                    {
                        certificateRequestCmc.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        var oInnerRequest = certificateRequestCmc.GetInnerRequest(InnerRequestLevel.LevelInnermost);
                        certificateRequest = oInnerRequest.get_RawData();
                    }
                    catch
                    {
                        result.Success = false;
                        result.Description.Add(LocalizedStrings.ReqVal_Err_Extract_From_Cmc);
                        result.StatusCode = WinError.NTE_FAIL;
                        return result;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certificateRequestCmc);
                        GC.Collect();
                    }

                    break;

                case CertCli.CR_IN_PKCS7:

                    // Short form would raise an E_NOINTERFACE exception on Windows 2012 R2 and earlier
                    var certificateRequestPkcs7 =
                        (IX509CertificateRequestPkcs7) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs7"));

                    // Try to open the Certificate Request
                    try
                    {
                        certificateRequestPkcs7.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        var oInnerRequest = certificateRequestPkcs7.GetInnerRequest(InnerRequestLevel.LevelInnermost);
                        certificateRequest = oInnerRequest.get_RawData();
                    }
                    catch
                    {
                        result.Success = false;
                        result.Description.Add(LocalizedStrings.ReqVal_Err_Extract_From_Pkcs7);
                        result.StatusCode = WinError.NTE_FAIL;
                        return result;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certificateRequestPkcs7);
                        GC.Collect();
                    }

                    break;
            }

            // Short form would raise an E_NOINTERFACE exception on Windows 2012 R2 and earlier
            var certificateRequestPkcs10 =
                (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                    Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));

            // Try to open the Certificate Request
            try
            {
                certificateRequestPkcs10.InitializeDecode(
                    certificateRequest,
                    EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                );
            }
            catch
            {
                result.Success = false;
                result.Description.Add(string.Format(LocalizedStrings.ReqVal_Err_Parse_Request, requestType));
                result.StatusCode = WinError.NTE_FAIL;
                return result;
            }

            #endregion

            #region Process request attributes

            string certClientMachine = null;

            // TODO: Put into method, and extract "rmd" as well, if present.

            // Log the name of the machine ("ccm" attribute) from where the request was submitted
            if (requestAttributeList != null &&
                requestAttributeList.Any(x => x.Key.Equals("ccm", StringComparison.InvariantCultureIgnoreCase)))
            {
                certClientMachine = requestAttributeList
                    .FirstOrDefault(x => x.Key.Equals("ccm", StringComparison.InvariantCultureIgnoreCase)).Value;
            }

            #endregion

            #region Process inline request attributes

            string processName = null;
            string machineDnsName = null;

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

                if (cryptAttribute.ObjectId.Value == SZOID_REQUEST_CLIENT_INFO)
                {
                    var clientId = new CX509AttributeClientId();

                    try
                    {
                        clientId.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64, rawData);
                        processName = clientId.ProcessName.ToLowerInvariant();
                        machineDnsName = clientId.MachineDnsName;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(clientId);
                    }
                }
            }

            #endregion

            #region Process rules for cryptographic providers

            if (certificateRequestPolicy.AllowedCryptoProviders != null &&
                certificateRequestPolicy.AllowedCryptoProviders.Count > 0 ||
                certificateRequestPolicy.DisallowedCryptoProviders != null &&
                certificateRequestPolicy.DisallowedCryptoProviders.Count > 0)
            {
                if (requestAttributeList != null &&
                    requestAttributeList.Any(x =>
                        x.Key.Equals("RequestCSPProvider", StringComparison.InvariantCultureIgnoreCase)))
                {
                    var cryptoProvider = requestAttributeList.FirstOrDefault(x =>
                            x.Key.Equals("RequestCSPProvider", StringComparison.InvariantCultureIgnoreCase))
                        .Value;

                    if (certificateRequestPolicy.AllowedCryptoProviders != null &&
                        !certificateRequestPolicy.AllowedCryptoProviders.Any(x =>
                            x.Equals(cryptoProvider, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Crypto_Provider_Not_Allowed,
                            cryptoProvider));
                    }

                    if (certificateRequestPolicy.DisallowedCryptoProviders != null &&
                        certificateRequestPolicy.DisallowedCryptoProviders.Any(x =>
                            x.Equals(cryptoProvider, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Crypto_Provider_Disallowed,
                            cryptoProvider));
                    }
                }
                else
                {
                    result.Success = false;
                    result.Description.Add(LocalizedStrings.ReqVal_Crypto_Provider_Unknown);
                }

                // Abort here to trigger proper error code
                if (result.Success == false)
                {
                    result.StatusCode = WinError.CERTSRV_E_TEMPLATE_DENIED;
                    return result;
                }
            }

            #endregion

            #region Process rules for the process name

            if (certificateRequestPolicy.AllowedProcesses != null &&
                certificateRequestPolicy.AllowedProcesses.Count > 0 ||
                certificateRequestPolicy.DisallowedProcesses != null &&
                certificateRequestPolicy.DisallowedProcesses.Count > 0)
            {
                if (processName != null)
                {
                    if (certificateRequestPolicy.AllowedProcesses != null &&
                        !certificateRequestPolicy.AllowedProcesses.Any(x =>
                            x.Equals(processName, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Process_Not_Allowed,
                            processName));
                    }

                    if (certificateRequestPolicy.DisallowedProcesses != null &&
                        certificateRequestPolicy.DisallowedProcesses.Any(x =>
                            x.Equals(processName, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Process_Disallowed,
                            processName));
                    }
                }
                else
                {
                    result.Success = false;
                    result.Description.Add(LocalizedStrings.ReqVal_Process_Unknown);
                }

                // Abort here to trigger proper error code
                if (result.Success == false)
                {
                    result.StatusCode = WinError.CERTSRV_E_TEMPLATE_DENIED;
                    return result;
                }
            }

            #endregion

            #region Process rules for requesting client computer

            // TODO

            #endregion

            if (templateInfo.EnrolleeSuppliesSubject)
            {
                #region Process rules for key attributes

                // Verify Key Algorithm
                string keyAlgorithm;

                switch (certificateRequestPkcs10.PublicKey.Algorithm.Value)
                {
                    case SZOID_ECC_PUBLIC_KEY:
                        keyAlgorithm = "ECC";
                        break;
                    case SZOID_RSA_RSA:
                        keyAlgorithm = "RSA";
                        break;
                    default:
                        keyAlgorithm = LocalizedStrings.Unknown;
                        break;
                }

                if (certificateRequestPolicy.KeyAlgorithm != keyAlgorithm)
                {
                    result.Success = false;
                    result.Description.Add(string.Format(LocalizedStrings.ReqVal_Key_Pair_Mismatch,
                        keyAlgorithm, certificateRequestPolicy.KeyAlgorithm));
                }

                if (certificateRequestPkcs10.PublicKey.Length < certificateRequestPolicy.MinimumKeyLength)
                {
                    result.Success = false;
                    result.Description.Add(string.Format(LocalizedStrings.ReqVal_Key_Too_Small,
                        certificateRequestPkcs10.PublicKey.Length, certificateRequestPolicy.MinimumKeyLength));
                }

                if (certificateRequestPolicy.MaximumKeyLength > 0)
                {
                    if (certificateRequestPkcs10.PublicKey.Length > certificateRequestPolicy.MaximumKeyLength)
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Key_Too_Large,
                            certificateRequestPkcs10.PublicKey.Length, certificateRequestPolicy.MaximumKeyLength));
                    }
                }

                // Abort here to trigger proper error code
                if (result.Success == false)
                {
                    result.StatusCode = WinError.CERTSRV_E_KEY_LENGTH;
                    return result;
                }

                #endregion

                #region Process Subject

                string subjectDn = null;

                try
                {
                    // Will trigger an exception if empty
                    subjectDn = certificateRequestPkcs10.Subject.Name;
                }
                catch
                {
                    // Subject is empty
                }

                // Convert the Subject DN into a List of Key Value Pairs for each RDN
                var subjectRdnList = new List<KeyValuePair<string, string>>();

                if (subjectDn != null)
                {
                    try
                    {
                        subjectRdnList = GetDnComponents(subjectDn);
                    }
                    catch
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Err_Parse_SubjectDn, subjectDn));
                        result.StatusCode = WinError.CERTSRV_E_BAD_REQUESTSUBJECT;
                        return result;
                    }
                }

                #endregion

                #region Process Subject Alternative Name

                // Convert the Subject Alternative Names into a List of Key Value Pairs for each entry
                var subjectAltNameList = new List<KeyValuePair<string, string>>();

                // Process Certificate extensions
                foreach (IX509Extension extension in certificateRequestPkcs10.X509Extensions)
                {
                    switch (extension.ObjectId.Value)
                    {
                        case XCN_OID_SUBJECT_ALT_NAME2:

                            var extensionAlternativeNames = new CX509ExtensionAlternativeNames();

                            extensionAlternativeNames.InitializeDecode(
                                EncodingType.XCN_CRYPT_STRING_BASE64,
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
                                            new KeyValuePair<string, string>("userPrincipalName", san.strValue));
                                        break;

                                    case AlternativeNameType.XCN_CERT_ALT_NAME_IP_ADDRESS:

                                        var b64IpAddress = san.get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64);
                                        var ipAddress = new IPAddress(Convert.FromBase64String(b64IpAddress));
                                        subjectAltNameList.Add(
                                            new KeyValuePair<string, string>("iPAddress", ipAddress.ToString()));

                                        break;

                                    default:

                                        result.Success = false;
                                        result.Description.Add(string.Format(
                                            LocalizedStrings.ReqVal_Unsupported_San_Type,
                                            san.ObjectId.Value));
                                        break;
                                }
                            }

                            Marshal.ReleaseComObject(extensionAlternativeNames);

                            break;

                        // The subject directory attributes extension can be used to convey identification attributes such as the nationality of the certificate subject.
                        // The extension value is a sequence of OID-value pairs.
                        case XCN_OID_SUBJECT_DIR_ATTRS:

                            // Not supported at the moment
                            result.Success = false;
                            result.Description.Add(LocalizedStrings.ReqVal_Unsupported_Extension_Dir_Attrs);
                            break;
                    }
                }

                #endregion

                #region Process rules for name constraints

                var subjectValidationResult = VerifySubject(
                    subjectRdnList,
                    certificateRequestPolicy.Subject
                );

                if (subjectValidationResult.Success == false)
                {
                    result.Success = false;
                    result.Description.AddRange(subjectValidationResult.Description);
                    result.StatusCode = WinError.CERT_E_INVALID_NAME;
                }

                var subjectAltNameValidationResult = VerifySubject(
                    subjectAltNameList,
                    certificateRequestPolicy.SubjectAlternativeName
                );

                if (subjectAltNameValidationResult.Success == false)
                {
                    result.Success = false;
                    result.Description.AddRange(subjectAltNameValidationResult.Description);
                    result.StatusCode = WinError.CERT_E_INVALID_NAME;
                }

                #endregion
            }

            Marshal.ReleaseComObject(certificateRequestPkcs10);
            GC.Collect();

            return result;
        }

        private static CertificateRequestVerificationResult VerifySubject(
            List<KeyValuePair<string, string>> subjectInfo, List<SubjectRule> subjectPolicy)
        {
            var result = new CertificateRequestVerificationResult();

            if (subjectInfo == null)
            {
                result.Success = false;
                return result;
            }

            // Cycle through defined RDNs and compare to present RDNs
            foreach (var definedItem in subjectPolicy)
            {
                // Count the occurrences of the currently inspected defined RDN, if any
                var occurrences = subjectInfo.Count(x =>
                    x.Key.Equals(definedItem.Field, StringComparison.InvariantCultureIgnoreCase));

                // Deny if a RDN defined as mandatory is missing
                if (occurrences == 0 && definedItem.Mandatory)
                {
                    result.Success = false;
                    result.Description.Add(string.Format(LocalizedStrings.ReqVal_Field_Missing, definedItem.Field));
                }

                // Deny if a RDN occurs too often
                if (occurrences > definedItem.MaxOccurrences)
                {
                    result.Success = false;
                    result.Description.Add(string.Format(LocalizedStrings.ReqVal_Field_Count_Mismatch,
                        definedItem.Field, occurrences, definedItem.MaxOccurrences));
                }
            }

            foreach (var subjectItem in subjectInfo)
            {
                var policyItem = subjectPolicy.FirstOrDefault(x =>
                    x.Field.Equals(subjectItem.Key, StringComparison.InvariantCultureIgnoreCase));

                if (policyItem == null)
                {
                    // Deny if a RDN is found that is not defined (therefore it is forbidden)
                    result.Success = false;
                    result.Description.Add(string.Format(LocalizedStrings.ReqVal_Field_Not_Allowed, subjectItem.Key));
                }
                else
                {
                    // Deny if the RDNs content deceeds the defined number of Characters
                    if (subjectItem.Value.Length < policyItem.MinLength)
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Field_Too_Short, subjectItem.Value,
                            subjectItem.Key, policyItem.MinLength));
                    }

                    // Deny if the RDNs content exceeds defined number of Characters
                    if (subjectItem.Value.Length > policyItem.MaxLength)
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Field_Too_Long, subjectItem.Value,
                            subjectItem.Key, policyItem.MaxLength));
                    }

                    // Process patterns
                    if (policyItem.Patterns == null)
                    {
                        result.Success = false;
                        result.Description.Add(
                            string.Format(LocalizedStrings.ReqVal_Field_Not_Defined, subjectItem.Key));
                        return result;
                    }

                    #region Deny if there aren't any allowed matches

                    var matchFound = false;

                    foreach (var pattern in policyItem.Patterns.Where(x => x.Action.Equals("Allow")))
                    {
                        if (VerifyPattern(subjectItem.Value, pattern))
                        {
                            matchFound = true;
                            break; 
                        }
                    }

                    if (!matchFound)
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_No_Match, subjectItem.Value,
                            subjectItem.Key));

                        return result;
                    }

                    #endregion

                    #region Deny if there is any disallowed match

                    foreach (var pattern in policyItem.Patterns.Where(x => x.Action.Equals("Deny")))
                    {
                        if (VerifyPattern(subjectItem.Value, pattern))
                        {
                            result.Success = false;
                            result.Description.Add(string.Format(LocalizedStrings.ReqVal_Disallow_Match, subjectItem.Value,
                                subjectItem.Key));

                            return result;
                        }
                    }

                    #endregion
                }
            }

            return result;
        }

        private static bool VerifyPattern (string term, Pattern pattern)
        {
            try
            {
                switch (pattern.TreatAs)
                {
                    case "RegEx":

                        var regEx = new Regex(@"" + pattern.Expression + "");
                        if (regEx.IsMatch(term))
                        {
                            return true;
                        }

                        break;

                    case "Cidr":

                        var ipAddress = IPAddress.Parse(term);
                        if (ipAddress.IsInRange(pattern.Expression))
                        {
                            return true;
                        }

                        break;
                }
            }
            catch
            {
                //
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
                case "OU": return "organizationalUnit";
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
            var outString = string.Empty;

            for (var i = 1; i < rdn.Length - 1; i++)
            {
                var currentChar = rdn[i];

                if (currentChar == quoteChar)
                {
                    if (inQuotedString == false)
                    {
                        outString += currentChar;
                    }

                    inQuotedString = !inQuotedString;
                }
                else
                {
                    outString += currentChar;
                }
            }

            return outString;
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

        public class CertificateRequestVerificationResult
        {
            public CertificateRequestVerificationResult(bool auditOnly = false)
            {
                AuditOnly = auditOnly;
            }

            public int StatusCode { get; set; } = WinError.ERROR_SUCCESS;
            public bool Success { get; set; } = true;
            public bool AuditOnly { get; }
            public List<string> Description { get; set; } = new List<string>();
        }
    }
}