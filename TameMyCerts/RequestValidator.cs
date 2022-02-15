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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;
using CERTENROLLLib;

namespace TameMyCerts
{
    public class CertificateRequestPolicy
    {
        public bool AuditOnly { get; set; }
        public string KeyAlgorithm { get; set; } = "RSA";

        public int MinimumKeyLength { get; set; }
        public int MaximumKeyLength { get; set; }
        public List<SubjectRule> Subject { get; set; }
        public List<SubjectRule> SubjectAlternativeName { get; set; }

        private static string ConvertToHumanReadableXml(string inputString)
        {
            var xmlWriterSettings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true,
                Indent = true,
                NewLineOnAttributes = true
            };

            var stringBuilder = new StringBuilder();

            var xElement = XElement.Parse(inputString);

            using (var xmlWriter = XmlWriter.Create(stringBuilder, xmlWriterSettings))
            {
                xElement.Save(xmlWriter);
            }

            return stringBuilder.ToString();
        }

        public void SaveToFile(string path)
        {
            var xmlSerializer = new XmlSerializer(typeof(CertificateRequestPolicy));

            using (var stringWriter = new StringWriter())
            {
                using (var xmlWriter = XmlWriter.Create(stringWriter))
                {
                    xmlSerializer.Serialize(xmlWriter, this);
                    var xmlData = stringWriter.ToString();

                    try
                    {
                        File.WriteAllText(path, ConvertToHumanReadableXml(xmlData));
                    }
                    catch
                    {
                        // fail silently
                    }
                }
            }
        }
    }

    public class SubjectRule
    {
        public string Field { get; set; } = string.Empty;
        public bool Mandatory { get; set; }
        public int MaxOccurrences { get; set; } = 1;
        public int MinLength { get; set; } = 1;
        public int MaxLength { get; set; } = 128;
        public List<string> AllowedPatterns { get; set; }
        public List<string> DisallowedPatterns { get; set; }
    }

    public class CertificateRequestValidator
    {
        private const string XCN_OID_SUBJECT_ALT_NAME2 = "2.5.29.17";
        private const string XCN_OID_SUBJECT_DIR_ATTRS = "2.5.29.9";
        private const string szOID_RSA_RSA = "1.2.840.113549.1.1.1";
        private const string szOID_ECC_PUBLIC_KEY = "1.2.840.10045.2.1";

        public CertificateRequestVerificationResult VerifyRequest(string certificateRequest,
            CertificateRequestPolicy certificateRequestPolicy, int requestType = CertCli.CR_IN_PKCS10)
        {
            var result = new CertificateRequestVerificationResult
            {
                AuditOnly = certificateRequestPolicy.AuditOnly
            };

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

            #region Verify key attributes

            // Verify Key Algorithm
            string keyAlgorithm;

            switch (certificateRequestPkcs10.PublicKey.Algorithm.Value)
            {
                case szOID_ECC_PUBLIC_KEY:
                    keyAlgorithm = "ECC";
                    break;
                case szOID_RSA_RSA:
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
                if (certificateRequestPkcs10.PublicKey.Length > certificateRequestPolicy.MaximumKeyLength)
                {
                    result.Success = false;
                    result.Description.Add(string.Format(LocalizedStrings.ReqVal_Key_Too_Large,
                        certificateRequestPkcs10.PublicKey.Length, certificateRequestPolicy.MaximumKeyLength));
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

            #endregion

            #region Process Subject Alternative Name

            // Convert the Subject Alternative Names into a List of Key Value Pairs for each entry
            var subjectAltNameList = new List<KeyValuePair<string, string>>();

            // Process Certificate extensions
            foreach (IX509Extension extension in certificateRequestPkcs10.X509Extensions)
                switch (extension.ObjectId.Value)
                {
                    case XCN_OID_SUBJECT_ALT_NAME2:

                        var extensionAlternativeNames = new CX509ExtensionAlternativeNames();

                        extensionAlternativeNames.InitializeDecode(
                            EncodingType.XCN_CRYPT_STRING_BASE64,
                            extension.get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64)
                        );

                        foreach (IAlternativeName san in extensionAlternativeNames.AlternativeNames)
                            switch (san.Type)
                            {
                                case AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME:

                                    subjectAltNameList.Add(new KeyValuePair<string, string>("dNSName", san.strValue));
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME:

                                    subjectAltNameList.Add(
                                        new KeyValuePair<string, string>("rfc822Name", san.strValue));
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_URL:

                                    subjectAltNameList.Add(
                                        new KeyValuePair<string, string>("uniformResourceIdentifier", san.strValue));
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
                                    result.Description.Add(string.Format(LocalizedStrings.ReqVal_Unsupported_San_Type,
                                        san.ObjectId.Value));
                                    break;
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

            #endregion

            Marshal.ReleaseComObject(certificateRequestPkcs10);
            GC.Collect();

            #region Verify Name constraints

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

            return result;
        }

        private static CertificateRequestVerificationResult VerifySubject(
            List<KeyValuePair<string, string>> subjectInfo, List<SubjectRule> subjectPolicy)
        {
            var result = new CertificateRequestVerificationResult();

            if (null == subjectInfo)
            {
                result.Success = false;
                return result;
            }

            // Cycle through defined RDNs and compare to present RDNs
            foreach (var definedItem in subjectPolicy)
            {
                // Count the occurrences of the currently inspected defined RDN, if any
                var occurrences = subjectInfo.Count(x => x.Key == definedItem.Field);

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
                var policyItem = subjectPolicy.FirstOrDefault(x => x.Field == subjectItem.Key);

                if (null == policyItem)
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

                    // Process allowed patterns
                    var allowedMatches = 0;

                    if (null == policyItem.AllowedPatterns)
                    {
                        result.Success = false;
                        result.Description.Add(
                            string.Format(LocalizedStrings.ReqVal_Field_Not_Defined, subjectItem.Key));
                        return result;
                    }

                    foreach (var pattern in policyItem.AllowedPatterns)
                        try
                        {
                            if (subjectItem.Key == "iPAddress")
                            {
                                var ipAddress = IPAddress.Parse(subjectItem.Value);

                                if (ipAddress.IsInRange(pattern))
                                    allowedMatches++;
                            }
                            else
                            {
                                var regEx = new Regex(@"" + pattern + "");

                                if (regEx.IsMatch(subjectItem.Value))
                                    allowedMatches++;
                            }
                        }
                        catch
                        {
                            result.Success = false;
                            result.Description.Add(string.Format(LocalizedStrings.ReqVal_Err_Regex, pattern,
                                subjectItem.Value, subjectItem.Key));
                        }

                    // Deny if there weren't any matches
                    if (allowedMatches == 0)
                    {
                        result.Success = false;
                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_No_Match, subjectItem.Value,
                            subjectItem.Key));
                    }

                    // Process disallowed patterns
                    if (null != policyItem.DisallowedPatterns)
                        foreach (var pattern in policyItem.DisallowedPatterns)
                            try
                            {
                                if (policyItem.Field == "iPAddress")
                                {
                                    var ipAddress = IPAddress.Parse(subjectItem.Value);
                                    if (ipAddress.IsInRange(pattern))
                                    {
                                        result.Success = false;
                                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Disallow_Match,
                                            subjectItem.Value, pattern, subjectItem.Key));

                                        // One is sufficient
                                        break;
                                    }
                                }
                                else
                                {
                                    // Stop if the RDN *does* match the defined pattern
                                    var regEx = new Regex(@"" + pattern + "");

                                    if (regEx.IsMatch(subjectItem.Value))
                                    {
                                        result.Success = false;
                                        result.Description.Add(string.Format(LocalizedStrings.ReqVal_Disallow_Match,
                                            subjectItem.Value, pattern, subjectItem.Key));

                                        // One is sufficient
                                        break;
                                    }
                                }
                            }
                            catch
                            {
                                result.Success = false;
                                result.Description.Add(string.Format(LocalizedStrings.ReqVal_Err_Regex, pattern,
                                    subjectItem.Value, subjectItem.Key));

                                break;
                            }
                }
            }

            return result;
        }

        public CertificateRequestPolicy LoadFromFile(string path)
        {
            var xmlSerializer = new XmlSerializer(typeof(CertificateRequestPolicy));

            try
            {
                using (var reader = new StreamReader(path))
                {
                    return (CertificateRequestPolicy) xmlSerializer.Deserialize(reader.BaseStream);
                }
            }
            catch
            {
                return null;
            }
        }

        public CertificateRequestPolicy GetSamplePolicy()
        {
            // This function can be used to write a sample XML based policy configuration file
            // This is not in active use by the policy module at the moment

            var policy = new CertificateRequestPolicy
            {
                KeyAlgorithm = "RSA",
                MaximumKeyLength = 4096,
                Subject = new List<SubjectRule>
                {
                    new SubjectRule
                    {
                        Field = "commonName",
                        Mandatory = true,
                        MaxLength = 64,
                        AllowedPatterns = new List<string>
                        {
                            @"^[-_a-zA-Z0-9]*\.adcslabor\.de$",
                            @"^[-_a-zA-Z0-9]*\.intra\.adcslabor\.de$"
                        },
                        DisallowedPatterns = new List<string>
                        {
                            @"^.*(porn|gambling).*$",
                            @"^intra\.adcslabor\.de$"
                        }
                    },
                    new SubjectRule
                    {
                        Field = "countryName",
                        MaxLength = 2,
                        AllowedPatterns = new List<string>
                        {
                            // ISO 3166 country codes as example... to ensure countryName is filled correctly (e.g. "GB" instead of "UK")
                            @"^(AD|AE|AF|AG|AI|AL|AM|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BL|BM|BN|BO|BQ|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|EH|ER|ES|ET|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MF|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|SS|ST|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TR|TT|TV|TW|TZ|UA|UG|UM|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)$"
                        }
                    },
                    new SubjectRule
                    {
                        Field = "organizationName",
                        MaxLength = 64,
                        AllowedPatterns = new List<string> {@"^ADCS Labor$"}
                    },
                    new SubjectRule
                    {
                        Field = "organizationalUnit",
                        MaxLength = 64,
                        AllowedPatterns = new List<string> {@"^.*$"}
                    },
                    new SubjectRule
                    {
                        Field = "localityName",
                        AllowedPatterns = new List<string>
                        {
                            // All capital cities of german federal states as example
                            @"^Bremen$",
                            @"^Hamburg$",
                            @"^Berlin$",
                            @"^Saarbruecken$",
                            @"^Kiel$",
                            @"^Erfurt$",
                            @"^Dresden$",
                            @"^Mainz$",
                            @"^Magdeburg$",
                            @"^Wiesbaden$",
                            @"^Schwerin$",
                            @"^Potsdam$",
                            @"^Duesseldorf$",
                            @"^Stuttgart$",
                            @"^Hanover$",
                            @"^Munich$"
                        }
                    },
                    new SubjectRule
                    {
                        Field = "stateOrProvinceName",
                        AllowedPatterns = new List<string>
                        {
                            // All german federal states as example
                            @"^Bremen$",
                            @"^Hamburg$",
                            @"^Berlin$",
                            @"^Saarland$",
                            @"^Schleswig Holstein$",
                            @"^Thuringia$",
                            @"^Saxony$",
                            @"^Rhineland Palatinate$",
                            @"^Saxony-Anhalt$",
                            @"^Hesse$",
                            @"^Mecklenburg Western Pomerania$",
                            @"^Brandenburg$",
                            @"^Northrhine-Westphalia$",
                            @"^Baden-Wuerttemberg$",
                            @"^Lower Saxony$",
                            @"^Bavaria$"
                        }
                    },
                    new SubjectRule
                    {
                        Field = "emailAddress",
                        AllowedPatterns = new List<string> {@"^[-_a-zA-Z0-9\.]*\@adcslabor\.de$"}
                    }
                },
                SubjectAlternativeName = new List<SubjectRule>
                {
                    new SubjectRule
                    {
                        Field = "dNSName",
                        MaxOccurrences = 10,
                        MaxLength = 64,
                        AllowedPatterns = new List<string>
                        {
                            @"^[-_a-zA-Z0-9]*\.adcslabor\.de$",
                            @"^[-_a-zA-Z0-9]*\.intra\.adcslabor\.de$"
                        },
                        DisallowedPatterns = new List<string>
                        {
                            @"^.*(porn|gambling).*$",
                            @"^intra\.adcslabor\.de$"
                        }
                    },
                    new SubjectRule
                    {
                        Field = "iPAddress",
                        MaxOccurrences = 10,
                        MaxLength = 64,
                        AllowedPatterns = new List<string> {@"192.168.0.0/16"},
                        DisallowedPatterns = new List<string>
                        {
                            @"192.168.123.0/24",
                            @"192.168.127.0/24",
                            @"192.168.131.0/24"
                        }
                    },
                    new SubjectRule
                    {
                        Field = "userPrincipalName",
                        MaxLength = 64,
                        AllowedPatterns = new List<string> {@"^[-_a-zA-Z0-9\.]*\@intra\.adcslabor\.de$"}
                    },
                    new SubjectRule
                    {
                        Field = "rfc822Name",
                        AllowedPatterns = new List<string> {@"^[-_a-zA-Z0-9\.]*\@adcslabor\.de$"}
                    }
                }
            };

            return policy;
        }

        public static string SubstituteRdnTypeAliases(string rdnType)
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
                // The default ones active on an ADCS CA
                case "C": return "countryName";
                case "CN": return "commonName";
                case "DC": return "domainComponent";
                case "E": return "emailAddress";
                case "L": return "localityName";
                case "O": return "organizationName";
                case "OU": return "organizationalUnit";
                case "S": return "stateOrProvinceName";

                // These can get enabled in addition to the default ones (in the SubjectTemplate registry key)
                case "G": return "givenName";
                case "I": return "initials";
                case "SN": return "surname";
                case "STREET": return "streetAddress";
                case "T": return "title";

                // These automatically get enabled if an NDES server gets deployed for the CA
                case "UNSTRUCTUREDNAME": return "unstructuredName";
                case "UNSTRUCTUREDADDRESS": return "unstructuredAddress";
                case "DEVICESERIALNUMBER": return "deviceSerialNumber";

                // These are only useable if the CRLF_REBUILD_MODIFIED_SUBJECT_ONLY flag is enabled on the CA, which allows
                // any subject DN to get specified by the enrollee. But this is fine when properly using this policy module
                case "POSTALCODE": return "postalCode";
                case "DESCRIPTION": return "description";
                case "POBOX": return "postOfficeBox";
                case "PHONE": return "telephoneNumber";

                // Unknown ones get returned as they are
                default: return rdnType;
            }
        }

        // If the subject RDN contains quotes or special characters, the IX509CertificateRequest interface escapes these with quotes
        // As this messes up our comparison logic, we must remove the additional quotes
        private static string RemoveQuotesFromSubjectRdn(string rdn)
        {
            if (null == rdn)
                return null;

            if (rdn.Length == 0)
                return rdn;

            // Not in quotes, nothing to do
            if (rdn[0] != '"' && rdn[rdn.Length - 1] != '"')
                return rdn;

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
                        outString += currentChar;

                    inQuotedString = !inQuotedString;
                }
                else
                {
                    outString += currentChar;
                }
            }

            return outString;
        }

        public static List<KeyValuePair<string, string>> GetDnComponents(string distinguishedName)
        {
            // Licensed to the .NET Foundation under one or more agreements.
            // The .NET Foundation licenses this file to you under the MIT license.

            // https://github.com/dotnet/corefx/blob/c539d6c627b169d45f0b4cf1826b560cd0862abe/src/System.DirectoryServices/src/System/DirectoryServices/ActiveDirectory/Utils.cs#L440-L449

            // First split by ','
            var components = Split(distinguishedName, ',');

            if (null == components)
                return null;

            var dnComponents = new List<KeyValuePair<string, string>>();

            for (var i = 0; i < components.GetLength(0); i++)
            {
                // split each component by '='
                var subComponents = Split(components[i], '=');

                if (subComponents.GetLength(0) != 2) throw new ArgumentException();

                var key = SubstituteRdnTypeAliases(subComponents[0].Trim());
                var value = RemoveQuotesFromSubjectRdn(subComponents[1].Trim());

                if (key.Length > 0)
                    dnComponents.Add(new KeyValuePair<string, string>(key, value));
                else
                    throw new ArgumentException();
            }

            return dnComponents;
        }

        public static string[] Split(string distinguishedName, char delimiter)
        {
            // Licensed to the .NET Foundation under one or more agreements.
            // The .NET Foundation licenses this file to you under the MIT license.

            // https://github.com/dotnet/corefx/blob/c539d6c627b169d45f0b4cf1826b560cd0862abe/src/System.DirectoryServices/src/System/DirectoryServices/ActiveDirectory/Utils.cs#L440-L449

            if (null == distinguishedName)
                return null;

            if (distinguishedName.Length == 0)
                return null;

            var inQuotedString = false;
            const char quoteChar = '\"';
            const char escapeChar = '\\';
            var nextTokenStart = 0;
            var resultList = new ArrayList();

            // get the actual tokens
            for (var i = 0; i < distinguishedName.Length; i++)
            {
                var currentChar = distinguishedName[i];

                if (currentChar == quoteChar)
                {
                    inQuotedString = !inQuotedString;
                }
                else if (currentChar == escapeChar)
                {
                    // skip the next character (if one exists)
                    if (i < distinguishedName.Length - 1) i++;
                }
                else if (!inQuotedString && currentChar == delimiter)
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
                    if (inQuotedString) throw new ArgumentException();

                    // we need to end the last token
                    resultList.Add(distinguishedName.Substring(nextTokenStart, i - nextTokenStart + 1));
                }
            }

            var results = new string[resultList.Count];
            for (var i = 0; i < resultList.Count; i++) results[i] = (string) resultList[i];
            return results;
        }

        public class CertificateRequestVerificationResult
        {
            public int StatusCode = WinError.ERROR_SUCCESS;
            public bool Success { get; set; } = true;

            public bool AuditOnly { get; set; }
            public List<string> Description { get; set; } = new List<string>();
        }
    }
}