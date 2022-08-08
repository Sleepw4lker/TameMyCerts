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
using System.ComponentModel;
using System.Globalization;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts;

namespace UnitTests
{
    // TODO: Test correct building of NotBefore Date (correct input, false input), when the feature is implemented
    // TODO: Subject DN with special chars that require escaping
    // TODO: Test the CertificateRequestPolicy Class against invalid and valid data

    [TestClass]
    public class RequestValidatorTests
    {
        private readonly CertificateRequestPolicy _requestPolicy;
        private readonly CertificateRequestValidator _requestValidator = new CertificateRequestValidator();
        private readonly string _standardCsr;
        private readonly CertificateTemplateInfo.Template _templateInfo;

        public RequestValidatorTests()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            _standardCsr =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDbTCCAlUCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApucZpFuF0+fvdL5C3jggO6vO\n" +
                "9PA39MnPG0VQBy1n2pdhD/WwIt3St6UuMTXyNzEqSqm396Dw6+1iLCcP4DioLywd\n" +
                "9rVHOAFmYNeahM24rYk9z+8rgx5a4GhtK6uSXD87aNDwz7l+QCnjapZu1bqfe/s+\n" +
                "Wzo3e/jiSNIUUiY6/DQnHcZpPn/nBruLih0muZFWCevIRwu/w05DMrX9KTKax06l\n" +
                "TJw+bQshKasiVDDW+0K5eDzvLu7cS6/Z9vVYHD7gGJNmX+YaJY+JS9tGaGyvDUiV\n" +
                "ww+Do5S8p13dXqY/xwMngkq3kkvTB8hstxE1pd07OQojZ1SaLFEyh3pX7abXMQID\n" +
                "AQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkqhkiG9w0B\n" +
                "CQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUsp05C4spRvndIOKWrM7O\n" +
                "aXVZLCUwPgYJKwYBBAGCNxUUMTEwLwIBBQwKb3R0aS1vdHRlbAwOT1RUSS1PVFRF\n" +
                "TFx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcNAgIxWDBWAgEAHk4ATQBp\n" +
                "AGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABv\n" +
                "AHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJKoZIhvcNAQELBQADggEB\n" +
                "ABCVBVb7DJjiDP5SbSpw08nvrwnx5kiQ21xR7AJmtSYPLmsmC7uIPxk8Jsq1hDUO\n" +
                "e2adcbMup6QY7GJGuc4OWhiaisKAeZB7Tcy5SEZIWe85DlkxEgLVFB9opmf+V3fA\n" +
                "d/ZtYS0J7MPg6F9UEra30T3CcHlH5Y8NlMtaZmqjfXyw2C5YkahEfSmk2WVaZiSf\n" +
                "8edZDjIw5eRZY/9QMi2JEcmSbq0DImiP4ou46aQ0U5iRGSNX+armMIhGJ1ycDXTM\n" +
                "SBDUN6qWGioX8NHTlUmebLijw3zSFMnIuYWhXF7FZ1IKMPySzVmquvBAjzT4kWSw\n" +
                "0bAr5OaOzHm7POogsgE8J1Y=\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            _templateInfo = new CertificateTemplateInfo.Template
            {
                EnrolleeSuppliesSubject = true
            };

            _requestPolicy = new CertificateRequestPolicy
            {
                KeyAlgorithm = "RSA",
                MinimumKeyLength = 2048,
                MaximumKeyLength = 4096,
                Subject = new List<SubjectRule>
                {
                    new SubjectRule
                    {
                        Field = "commonName",
                        Mandatory = true,
                        MaxLength = 64,
                        Patterns = new List<Pattern>
                        {
                            new Pattern {Expression = @"^[-_a-zA-Z0-9]*\.adcslabor\.de$"},
                            new Pattern {Expression = @"^[-_a-zA-Z0-9]*\.intra\.adcslabor\.de$"},
                            new Pattern {Expression = @"^.*(porn|gambling).*$", Action = "Deny"},
                            new Pattern {Expression = @"^intra\.adcslabor\.de$", Action = "Deny"}
                        }
                    },
                    new SubjectRule
                    {
                        Field = "countryName",
                        MaxLength = 2,
                        Patterns = new List<Pattern>
                        {
                            // ISO 3166 country codes as example... to ensure countryName is filled correctly (e.g. "GB" instead of "UK")
                            new Pattern
                            {
                                Expression =
                                    @"^(AD|AE|AF|AG|AI|AL|AM|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BL|BM|BN|BO|BQ|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|EH|ER|ES|ET|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MF|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|SS|ST|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TR|TT|TV|TW|TZ|UA|UG|UM|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)$"
                            }
                        }
                    },
                    new SubjectRule
                    {
                        Field = "organizationName",
                        MaxLength = 64,
                        Patterns = new List<Pattern> {new Pattern {Expression = @"^ADCS Labor$"}}
                    },
                    new SubjectRule
                    {
                        Field = "organizationalUnitName",
                        MaxLength = 64,
                        Patterns = new List<Pattern> {new Pattern {Expression = @"^.*$"}}
                    },
                    new SubjectRule
                    {
                        Field = "localityName",
                        Patterns = new List<Pattern>
                        {
                            // All capital cities of german federal states as example
                            new Pattern {Expression = @"^Bremen$"},
                            new Pattern {Expression = @"^Hamburg$"},
                            new Pattern {Expression = @"^Berlin$"},
                            new Pattern {Expression = @"^Saarbruecken$"},
                            new Pattern {Expression = @"^Kiel$"},
                            new Pattern {Expression = @"^Erfurt$"},
                            new Pattern {Expression = @"^Dresden$"},
                            new Pattern {Expression = @"^Mainz$"},
                            new Pattern {Expression = @"^Magdeburg$"},
                            new Pattern {Expression = @"^Wiesbaden$"},
                            new Pattern {Expression = @"^Schwerin$"},
                            new Pattern {Expression = @"^Potsdam$"},
                            new Pattern {Expression = @"^Duesseldorf$"},
                            new Pattern {Expression = @"^Stuttgart$"},
                            new Pattern {Expression = @"^Hanover$"},
                            new Pattern {Expression = @"^Munich$"}
                        }
                    },
                    new SubjectRule
                    {
                        Field = "stateOrProvinceName",
                        Patterns = new List<Pattern>
                        {
                            // All german federal states as example
                            new Pattern {Expression = @"^Bremen$"},
                            new Pattern {Expression = @"^Hamburg$"},
                            new Pattern {Expression = @"^Berlin$"},
                            new Pattern {Expression = @"^Saarland$"},
                            new Pattern {Expression = @"^Schleswig Holstein$"},
                            new Pattern {Expression = @"^Thuringia$"},
                            new Pattern {Expression = @"^Saxony$"},
                            new Pattern {Expression = @"^Rhineland Palatinate$"},
                            new Pattern {Expression = @"^Saxony-Anhalt$"},
                            new Pattern {Expression = @"^Hesse$"},
                            new Pattern {Expression = @"^Mecklenburg Western Pomerania$"},
                            new Pattern {Expression = @"^Brandenburg$"},
                            new Pattern {Expression = @"^Northrhine-Westphalia$"},
                            new Pattern {Expression = @"^Baden-Wuerttemberg$"},
                            new Pattern {Expression = @"^Lower Saxony$"},
                            new Pattern {Expression = @"^Bavaria$"}
                        }
                    },
                    new SubjectRule
                    {
                        Field = "emailAddress",
                        Patterns = new List<Pattern>
                            {new Pattern {Expression = @"^[-_a-zA-Z0-9\.]*\@adcslabor\.de$"}}
                    }
                },
                SubjectAlternativeName = new List<SubjectRule>
                {
                    new SubjectRule
                    {
                        Field = "dNSName",
                        MaxOccurrences = 10,
                        MaxLength = 64,
                        Patterns = new List<Pattern>
                        {
                            new Pattern {Expression = @"^[-_a-zA-Z0-9]*\.adcslabor\.de$"},
                            new Pattern {Expression = @"^[-_a-zA-Z0-9]*\.intra\.adcslabor\.de$"},
                            new Pattern {Expression = @"^.*(porn|gambling).*$", Action = "Deny"},
                            new Pattern {Expression = @"^intra\.adcslabor\.de$", Action = "Deny"}
                        }
                    },
                    new SubjectRule
                    {
                        Field = "iPAddress",
                        MaxOccurrences = 10,
                        MaxLength = 64,
                        Patterns = new List<Pattern>
                        {
                            new Pattern {Expression = @"192.168.0.0/16", TreatAs = "Cidr"},
                            new Pattern {Expression = @"192.168.123.0/24", TreatAs = "Cidr", Action = "Deny"},
                            new Pattern {Expression = @"192.168.127.0/24", TreatAs = "Cidr", Action = "Deny"},
                            new Pattern {Expression = @"192.168.131.0/24", TreatAs = "Cidr", Action = "Deny"}
                        }
                    },
                    new SubjectRule
                    {
                        Field = "userPrincipalName",
                        MaxLength = 64,
                        Patterns = new List<Pattern>
                        {
                            new Pattern {Expression = @"^[-_a-zA-Z0-9\.]*\@intra\.adcslabor\.de$"}
                        }
                    },
                    new SubjectRule
                    {
                        Field = "rfc822Name",
                        Patterns = new List<Pattern>
                        {
                            new Pattern {Expression = @"^[-_a-zA-Z0-9\.]*\@adcslabor\.de$"}
                        }
                    }
                }
            };
        }

        public void PrintResult(CertificateRequestValidationResult validationResult)
        {
            Console.WriteLine("0x{0:X} ({0}) {1}.", validationResult.StatusCode,
                new Win32Exception(validationResult.StatusCode).Message);
            Console.WriteLine(string.Join("\n", validationResult.Description));
        }

        [TestMethod]
        public void Deny_not_a_CSR()
        {
            const string request = "This is not a certificate request";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.NTE_FAIL));
        }

        [TestMethod]
        public void Allow_commonName_valid()
        {
            var validationResult = _requestValidator.VerifyRequest(_standardCsr, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Allow_commonName_valid_countryName_valid()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de,C=DE
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDejCCAmICAQAwLTELMAkGA1UEBhMCREUxHjAcBgNVBAMTFWludHJhbmV0LmFk\n" +
                "Y3NsYWJvci5kZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANYahn0j\n" +
                "JPGIDShHX+SzFMI9XnAN9iky4siQQV7TcpkJ78+S+ZJ+5o8io6AwTXiZt60ox9Yj\n" +
                "wp29PawCCVKeDKuY8sjoiOPqo3pUg0WeXCrD3zKKimb0TF4RSwCg+Ymf19MdeywF\n" +
                "jO+7oWzDheQV+UuIm+cT4ipqgIfkML6iphyy1SWxXl1jYCl5yrnSrG/9iz2eZdpl\n" +
                "WtDQX6FVaixWbJhdy9Wtk/b0mj5I27yapwjiG+cvVuaQ9S2iVR4N0rqVirNPLQgf\n" +
                "+V7UJbUIQCmklqU3oeAWXY7k9ryW8FTeQPEAZD9611C7A0EANm2EUVP+iJ08iUIy\n" +
                "S1AUSVLqopBjEf0CAwEAAaCCAQYwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE5MDQ0\n" +
                "LjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFCyR\n" +
                "TDtg3TJPfsJBNynovfc2dt+8MD4GCSsGAQQBgjcVFDExMC8CAQUMCm90dGktb3R0\n" +
                "ZWwMDk9UVEktT1RURUxcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3DQIC\n" +
                "MVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAA\n" +
                "SwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMA0GCSqG\n" +
                "SIb3DQEBCwUAA4IBAQCekmxgcJmTixtnAnWpj4ClO9WS5zJQIBmW9lC9E4zDHY7t\n" +
                "ZEaBkmdbf3lPmeMt9+/t46G97qt+zGpodJIXCquTPnAzVRNzJsTLC9G7pK557Jd0\n" +
                "55wOmhQ7nAhaR8wGHAhowSkiJDwthEEP4JUVhPmmG8fxBam4+NveaLVtmmM2HK/M\n" +
                "D6F1YJ0Jateh0gU/DSnD95xrXngfTzrKBhtD7VQrBXsbfpeysjjFfwqWNPR9cBNV\n" +
                "U1QKopiXRbWStlv0KFAJ7gHVNEkmAA00mbaEufmHbAOr2z/8RcrTRgK6Q14Ib/YP\n" +
                "P7MNEhROVnD5RdVp793twbYgnyLW4+UIbaKYX+t5\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Deny_key_is_ECC_but_must_be_RSA()
        {
            // NISTP256 Key
            // CN=intranet.adcslabor.de
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIB5DCCAYoCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMFkw\n" +
                "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuMAntMo/tF+VJie+0Ou/VWJw97zFvZ3D\n" +
                "013S3Dbh0mTQb6km47IHX3DD5KBW6Ks8iAec3qvr+jYnYjHKZFEuZ6CCAQYwHAYK\n" +
                "KwYBBAGCNw0CAzEOFgwxMC4wLjE5MDQ0LjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNV\n" +
                "HQ8BAf8EBAMCB4AwHQYDVR0OBBYEFChDMOcwzSJNbIlwS6/SYZFvkv27MD4GCSsG\n" +
                "AQQBgjcVFDExMC8CAQUMCm90dGktb3R0ZWwMDk9UVEktT1RURUxcdXdlDA5wb3dl\n" +
                "cnNoZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
                "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
                "UAByAG8AdgBpAGQAZQByAwEAMAoGCCqGSM49BAMCA0gAMEUCIQDvknuOQ52q4iMv\n" +
                "yEhQ5WYYq+7OvfmyVdDZcSoO/b1IkwIgTS/9EQNud7IuxW/639FxV+oS4PIssYn5\n" +
                "zEjZoYSctNw=\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
        }

        [TestMethod]
        public void Deny_key_is_RSA_but_must_be_ECC()
        {
            var requestPolicy = _requestPolicy;
            requestPolicy.KeyAlgorithm = "ECC";

            var validationResult = _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
        }

        [TestMethod]
        public void Deny_key_too_small()
        {
            // 1024 Bit Key
            // CN=intranet.adcslabor.de
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIICdDCCAd0CAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIGf\n" +
                "MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4gudRrmHIWnEofR6eoXBVXsyuzEgl\n" +
                "3ZNW2I3pKmp3TDIYhdS0pXbyJarwk7KkCs/r9nwc3lwmT3N3Xb1Aav6pbLbDsnwz\n" +
                "nhEtG7RKaz+nqfl9DZ2mKZpq/GohY7GCDaPX4ExXghdOGt1UDvZYAdp/JQ3q0RZw\n" +
                "saOym41igzzLyQIDAQABoIIBEjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTgzNjMu\n" +
                "MjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU77iM\n" +
                "Ld0M+XI10iyyIjiSep/AoLMwSgYJKwYBBAGCNxUUMT0wOwIBBQwaQ0xJRU5UMi5p\n" +
                "bnRyYS5hZGNzbGFib3IuZGUMCklOVFJBXHJ1ZGkMDnBvd2Vyc2hlbGwuZXhlMGYG\n" +
                "CisGAQQBgjcNAgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0\n" +
                "AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABl\n" +
                "AHIDAQAwDQYJKoZIhvcNAQELBQADgYEAZNh5xaK9rY1/u2UstSP6p4cz7YU/c28l\n" +
                "J2x0QJYmIwHg7yaSpYMY2UhVbb7Mp6+0O+IVSajHOYenUE3BEOaCcIZphbp4kzIy\n" +
                "TEnrYEPMbeHF2b1oK65mxdBOL4pdSEg6kHzmP7WvT5XHEmjDdcGSa413lwDIcYCr\n" +
                "JMXiY0xmEBg=\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
        }

        [TestMethod]
        public void Deny_key_too_large()
        {
            // 8192 Bit Key
            // CN=intranet.adcslabor.de
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIJeTCCBWECAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIE\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEAwZPi+tCoTBT2TQ2lu2FTVuZ5\n" +
                "Mli5r1fwPH2Pvymja0RGtspOu5vCWAMi5esyTJka/PfU/kgBOuDMzMRWepyHwMlN\n" +
                "shVWEDNKzYT7GcnELzgKFKBfbiiVvPshXEzr13cT+lKyioihrL5g1ksOV+NqSm4+\n" +
                "Iq6KOPRTxcqvJT5G96mVZ3TsfcQKB2OlATzo8DHXVqPS9dM6hnnMbOK2l7ohg1Q4\n" +
                "XC5zzmR1diajzrsFECGTjJRljxm2gtlth3aZXSE4Ep9FQxcc0/BBWMaltMHyeqaF\n" +
                "3a/g4+KjCtRrMeK+NIiJFHxIVlroclY8s59lu+ekqsSoq/vU8nLpRQV5R0D8ER0a\n" +
                "Lmx/tlRT4PiX1W6dbe0rqQGcF6vi8vmaKhcrc60suUex/5CP0i+bDfhkmU0x/s+y\n" +
                "khcr0+yl/FnUOAPLMSerYQZfQVYaZeTK7/bWi+5jySVjagZM752mf8KKWDFqavZU\n" +
                "tDlEu3wZA+kI7ziZsurT8dy8IhRE5QGSLYFExXj2W+D9N4IZZObPGeALc2N50Q1F\n" +
                "dznOwdXVyTlAhGbGvF67/FAdPs0HXBRSiRxogSwcDDdVw9wp0aXySaA7rx55agqR\n" +
                "04WBoSg6ELW3se4M+/EAU2dnC6BB6QLV7gcwGk8+9S4GHL8TguaecYrQwreqMBi9\n" +
                "JhVSa2HgsNBOxLySkAm9UCihlVyk6suPrOF6yE+PRuyPAd2bTbQrBUhm8JNGLWFC\n" +
                "NXvLHN+LOzxBxe3v5npkq/L/CUIPxBuuAuq1OjMsfzfWo5iCZx7R/0SCJbu9c2Ay\n" +
                "MxA3/NeFUF1kNkj7+Y8qUCq8EUvZp8INJBiVCfD/G5kQO4SD0/XZWVqGXs8La0A1\n" +
                "Yk53+Ez7PDLGmC35cA6oO3rFNZAsVZT+EON5t3JWrIt0+RhwQhdNbXtsd2pnewmz\n" +
                "CneCh+hn1iglqO/QpDEg6hXYx8lkwy8vjqrO4rjrwbMJYwZDmRam/eweap5/boBr\n" +
                "nttYrYagjhw/BHBd5aFb1Mk+0rbRd2w08LObC1gdjJxgOi+fc3Z1r8Hn+Bd7GeID\n" +
                "V5Sp3H+2qUdeHiuui/7fwCA/pIT2siWefBH7HZ3eMip9wx7Mm4q3mv4Ie9jyEShg\n" +
                "D+lx1IlTgf37Byq2NhsC9Ph7kdLFW1iAojyZ5UTLugGm7JKruybXcRITBFDTXQsB\n" +
                "0cQ3i+JsBxC9xX4/u9Ph/wH9QiX0h5hwzSY5S2IfjYeeXfiCEG7lKgR0UpqKPWrZ\n" +
                "77eTWXwoSdjzfBqDu3TjXsdwRDbrxOk/iVeC+tN4h/cjJdBB4OOAdHFRFHKobqoU\n" +
                "KFGJD6NpdUklRu9K1M95M4wh+Qe7QJjYKvTCuMzW34v11A7htDsDMtk9lDggQQID\n" +
                "AQABoIIBEjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTgzNjMuMjA+BgkqhkiG9w0B\n" +
                "CQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU7qxAt+UX4mKIM29ua/1t\n" +
                "zw5Y1kowSgYJKwYBBAGCNxUUMT0wOwIBBQwaQ0xJRU5UMi5pbnRyYS5hZGNzbGFi\n" +
                "b3IuZGUMCklOVFJBXHJ1ZGkMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcNAgIx\n" +
                "WDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABL\n" +
                "AGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJKoZI\n" +
                "hvcNAQELBQADggQBABqsWv1ziFWM2QHMU5Rz/WqTT6Aw26RyQpzBXoJWaMnzbdKz\n" +
                "4RdXbe+9wNkJ3JGOlOSWpCLkX4P7/GlH1Y0PGpdstyOWIvAra/DM2Aea+aQj0tN7\n" +
                "m7Kah0VtyPwHyFi8V5P9BCJnm0LpeIwdI6ar1tKeLfhSWFnKR+jiCKg+Os8K8ZjK\n" +
                "Y9170FdR8VgYqqnRTHNl1sep9xaeDu0/soxURjRuejBJsNyVfo/IpeJ/RT5tYLAv\n" +
                "j66BIA7cZXvgPqb7pagstnl3Zi9wqwVc0En/aWz7enUCi9NMfAvKfgU3dD5/1MFv\n" +
                "AUwlcPCDnVjVhm47R7Tqae60k/NsS70GHBep7O8xirnERPLK0L/5e2zA0+FSyatA\n" +
                "IS+lAxNvTN6wlwLd9FueAM+ZT99cCf/GT16Q8I/nfVzXeqmXtPxDr/2av2Jrqpvr\n" +
                "mmbOTjI6iq0Mb2R360+wz/VOLve0ewgMqIl5GRGWIjou2tg7eojWpN/UcXQwIHwK\n" +
                "TZ0bi6KD0cqbgsx2UATxU/DQNSJG7p4b0Nx3aJxTUkgCEbDJgnxXpwu+tKOUMSwB\n" +
                "qQ3WzHuP8hvrYl43lrPR0at3P7d/rHCjK7jpMPMnfQVZq4qZiXBV+04Mr/OmOe19\n" +
                "eOh+Te26Q4XAj+G1QsIzlR6JEH89sWvrIDS4mmncY/K9cJU8jrLuUgatTM2N3IA4\n" +
                "WWNQ1IEARGexnRdpzdatgjHdQHCL2bvm8DHeiYoAGqJrubtHxKhbzF7fXavNw+gU\n" +
                "LCP9UxdlTaYF0Q2k5UgBzcipJtKljpxtGabRnFu9ZTm2AGuBk4rc4CpwN8d1E8VB\n" +
                "lhZQoPo3ParvfdxVilptEg8F76FY5SP9a3x2G9Kloi/gQ8r1DetaKAqet4pXq1EO\n" +
                "TFVG430dCbYbTHyujp1JhLCYF14j3Wdn19YSYGvu6BATj+0XCHHn2XB+NEQZGrGB\n" +
                "WEGZx+FqkDt3shZk+sKmRmy23zdI6zx3AMNw62hMc928Yix5fDNYoDmojPb+KmjH\n" +
                "JrfGY4gM2thMGqY8QBThpHxzZK4GSB4Xr+MECghHXvKO7au3/1XpO3R7kDsQpBAJ\n" +
                "t/vK3FKraiRUp5Lf7QzTOh6y3OZAT9++4/1Ww6T7NaaQUVKd3dqAc/CB6LL2+tBN\n" +
                "Ee5IHeZeNwslPcRYuDeW/ljF5P1EgXhQB+0udEuZARXInr8Izze1/RU+Y1nwgT8B\n" +
                "HREOjcHzO9+VD89lUTKRLGrlHpC4//3uiP/PZTIuqjfKMXWwdLb7gbwYfud3icag\n" +
                "zANi1N+s7o6SPRh8EjnmAnhIdv3KRv+kXurRqJ/KVXjF71r33aGfg9l3d+25ke+h\n" +
                "zt7jEmioXNz+JZOwmQ3Z0l+5cqwOrxSuSWmzun0=\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
        }


        [TestMethod]
        public void Allow_commonName_valid_ECC_key()
        {
            // NISTP256 Key
            // CN=intranet.adcslabor.de
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIB5TCCAYoCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMFkw\n" +
                "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOCI+dwMwFiVag2RMSiSbJZaMYpQWwjOG\n" +
                "M7DNAb/lwfuj8/iHwD65zVmOOo8bI718nG1K+rrL/pQM1oARFRTfX6CCAQYwHAYK\n" +
                "KwYBBAGCNw0CAzEOFgwxMC4wLjE5MDQ0LjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNV\n" +
                "HQ8BAf8EBAMCB4AwHQYDVR0OBBYEFMBnQ3exgZqATetKob7bmZ2c4LFHMD4GCSsG\n" +
                "AQQBgjcVFDExMC8CAQUMCm90dGktb3R0ZWwMDk9UVEktT1RURUxcdXdlDA5wb3dl\n" +
                "cnNoZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
                "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
                "UAByAG8AdgBpAGQAZQByAwEAMAoGCCqGSM49BAMCA0kAMEYCIQD2DC7IZUOeTAo0\n" +
                "+MK1AfT+JXL2vMrefDpJFTryK398lQIhAJe4wTQP2xpOVAtjPRUcaftqsl9fVOum\n" +
                "pMl8kKH3yqXI\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var requestPolicy = _requestPolicy;
            requestPolicy.KeyAlgorithm = "ECC";
            requestPolicy.MinimumKeyLength = 256;

            var validationResult = _requestValidator.VerifyRequest(request, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Allow_commonName_valid_dnsName_valid()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // dnsName=intranet.adcslabor.de
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDkjCCAnoCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3GmfcSDSunQ6+vmz9mTHcEKg\n" +
                "DMzDSXj0lQ7Erazl9CJ4WzROZaa1BUITfRlVXreku6ljYsO3jyTDBRBtCUXNwFk+\n" +
                "MTmzTqXx82MRpK2ATDp2jEPfP7l7K30DwDyiapkpaAvZlxIVWtIDoGxAG+yRFjAF\n" +
                "Qh4HDvSaBoaNvwdjZsUcdgOuJQbIwBhto/RB+4L23oT7+8e2GyRMm/bQK2gDvCbV\n" +
                "9SwTwm9gXljth0wuZ8RRkC7MMVIiPaxUH575SUKE7YvHeZ4Hq20Q2XYBSigqNXBM\n" +
                "VCUVCfsBGA18/MR/ZMFSSCIt2KLjkpp5q9gOCibw0oPrGTqUoLtCkLREbMrHbQID\n" +
                "AQABoIIBKzAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
                "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
                "bC5leGUwYwYJKoZIhvcNAQkOMVYwVDAOBgNVHQ8BAf8EBAMCB4AwIwYDVR0RAQH/\n" +
                "BBkwF4IVaW50cmFuZXQuYWRjc2xhYm9yLmRlMB0GA1UdDgQWBBRmh46ij+b3RODb\n" +
                "JXIj5NFC58DFZzBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
                "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
                "UAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBAQAmQ8B9fZ+ewB3+\n" +
                "kDFsJcqeMJ+nbFBcHJKmKfhn9564tiBZayK8kpkTvS1Cjb5C79Yimimw2AqGqdFK\n" +
                "W3+wWPCkFN996GoXFOU+lg3I5Byz3Eq4Vyv/H7RCufC68ezVG5v4EaqE4TsYcfoE\n" +
                "zH8HJu0jKKf+QKj9LpXI+HYLwvQ0Fyz4lr839NMidsPF4AWMpEXs/2OSTjg5qDVj\n" +
                "LKMPzd0wrOea0XWx2fEeibdW+KFi1656J+OIGuYP/q0SaPqYgFey+kOS2KLz+9/r\n" +
                "CA+TvKzFxxgRPAfA0TO7GAuwspV2wLOfXVOxIpG5GkmpxeK0nZvyw9HvxWWNlkgw\n" +
                "kbUQqV43\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Allow_commonName_valid_ipAddress_valid()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // ipAddress=192.168.0.1
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDgTCCAmkCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAssXMb23gWNQPuO2OtHubWSIH\n" +
                "f05rvRfHr4pRmMoI3JFuwnTHs5ho3sLtLu/NOroH5xUAthC/OJoUFOusu/9vlptf\n" +
                "8oPABXvHRCuCsEhdfGB/+p7Wf/FMm+YU9KhwNUM1kt1wQ2XAFKEi11iaF8YkzyQ1\n" +
                "PP8zqRU0UNEXlF1GWgc1DOnOkKKkZS2jE1LQ6yBm+suD++EMGPUH+7OSNDGvtWEM\n" +
                "D9LMhH+vcdYpABJbz7jzjytIXmayEQM4oz8CT/2NfRMzSeMOheDCILJugK43A+qe\n" +
                "BpTfie0LA99vYFIHe4vh7Mxc+FR+aHL3dP3doQnt98a0R14XnNn/uUadA46C2QID\n" +
                "AQABoIIBGjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
                "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
                "bC5leGUwUgYJKoZIhvcNAQkOMUUwQzAOBgNVHQ8BAf8EBAMCB4AwEgYDVR0RAQH/\n" +
                "BAgwBocEwKgAATAdBgNVHQ4EFgQUhkzXt+AAu7HigUpHv45MuccLo/IwZgYKKwYB\n" +
                "BAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBh\n" +
                "AHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcgMB\n" +
                "ADANBgkqhkiG9w0BAQsFAAOCAQEAb0k413f2rAuTtb3cmS3e0w2jLR71d8+OZZ4w\n" +
                "HN618i5xc/1boSY7p/M5rWRbZp4xdtpwYtUFOsUxuOrZdTjYckY6i834r9xZ9BCP\n" +
                "cw3V0FISgyZ1g5lIkV1rQW2V66ZA3SVyzXoPQQ0AJBMdiudIbFsg1BJ3LwmIjuGS\n" +
                "4TF3unbiVDFNXchtwICznn2OFPWPeGnz37xRiuWK7rheXOU+KHWHaVUpyar8J+5O\n" +
                "RRsjitR+Lgqvm/KYUacA5TARMVhGjPzS4O42VYCGjlMR74YaQi+LH3Vezft5G/Ft\n" +
                "CpV76XuDMJqMk4VrPkh1rLljbGqKzuQzIuCVAPFBhsLCqnHByQ==\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Allow_commonName_valid_dnsName_at_maximum()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // dnsName=web1.adcslabor.de,web2.adcslabor.de,web3.adcslabor.de,web4.adcslabor.de,web5.adcslabor.de,web6.adcslabor.de,web7.adcslabor.de,web8.adcslabor.de,web9.adcslabor.de,web10.adcslabor.de
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIEQjCCAyoCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4nercj9Ulpkk27qrG1jcDmMW\n" +
                "xIRtHPvXOZKTvkN5JYFP7elCwKUHATcECdNwY9hTKDzompL+cS73L6myuzl2oFCs\n" +
                "R/Yhgwf4IRVUjN15sImi8E2VBe7CLbfFstu0ss4wkbHQqY9W3fMjJ5hC4nlJq1iR\n" +
                "kr4qdpZ4ou/D8vxg7hhVbEivSrZ2F1S6erpMlW82S9LIN/OP5fgYKfsHU3KGzCnd\n" +
                "VD/mB6BFDWk5rOgCrgb+ZtfRyaJBQmADHsIhmdx19ZASrVrj3MCED/Sg0YCsZ6hA\n" +
                "rYBxFupzweAMkXcA3ldOXCybLiVdCRkVX3/MWys2/QQOSo1JemWOQ6udKAW0pQID\n" +
                "AQABoIIB2zAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
                "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
                "bC5leGUwZgYKKwYBBAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAg\n" +
                "AFMAbwBmAHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBv\n" +
                "AHYAaQBkAGUAcgMBADCCAREGCSqGSIb3DQEJDjGCAQIwgf8wDgYDVR0PAQH/BAQD\n" +
                "AgeAMIHNBgNVHREBAf8EgcIwgb+CEXdlYjEuYWRjc2xhYm9yLmRlghF3ZWIyLmFk\n" +
                "Y3NsYWJvci5kZYIRd2ViMy5hZGNzbGFib3IuZGWCEXdlYjQuYWRjc2xhYm9yLmRl\n" +
                "ghF3ZWI1LmFkY3NsYWJvci5kZYIRd2ViNi5hZGNzbGFib3IuZGWCEXdlYjcuYWRj\n" +
                "c2xhYm9yLmRlghF3ZWI4LmFkY3NsYWJvci5kZYIRd2ViOS5hZGNzbGFib3IuZGWC\n" +
                "EndlYjEwLmFkY3NsYWJvci5kZTAdBgNVHQ4EFgQU+yk1zDDNwJLRaRyZ5F5S0NCG\n" +
                "3NkwDQYJKoZIhvcNAQELBQADggEBAHPuyBtJ+Qfnrd8G3sqDyGqYZrVbeZr9OX5X\n" +
                "frw5witZSgz7miEC8Mk4AsU2yAEllCPgblzVnXakw+bGF4NRm8UoDoODhTLSOlxI\n" +
                "yyTpGzKGWm6PuHzx+99DiueHRZ0SPpQXdg3wCram7wlP3YLpAW4z8DaPkDAs1t3D\n" +
                "s6GFEzzriYHsSCI8xv1O6eQemORKnPP8gqfhWwn8uf9RkHZ2yFDbMMCySwiiFAPo\n" +
                "W0qGy6WU15+a7PlOVcbsC4Bbqy6FGIV6BaZ/Be9OAzDuoaX6p7Wz7hk6y71XZPaP\n" +
                "sicnx80RxPqTLH3kpX+8egvRxSmXt9rX3adVaOnrXvvEzj7kQzA=\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Deny_ipAddress_invalid()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // ipAddress=172.16.0.1
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDgTCCAmkCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmpqmUV/QKVRdWY8C8VFl4BZ/\n" +
                "/M/lr0Um8BGgz8Nv4He7XTLjOE5C89D9REMjlY8n6AYE0sb+YQ/23guRwYjTPtNp\n" +
                "V41VFexQraXvRDYSNOP0zJan3mZh6tzOI08J7L38Sp7pSHzVwdK64sdKOvvu+Um8\n" +
                "Z9A02+Y4VDV8BAUrF7HRKcglL2GwK2VqOTr2BW1aU9+jk/FsyTpeORZqPuXHGleA\n" +
                "8vDt1bzWbPnPOmDhV4oCAyo0JfhtXZS4zTmWYtwQpQ9ZG2TypmZvIXX4Q4511Wm8\n" +
                "V5uYRBaeSk5xz+aXMFIUBdyYAnF6LY83MnPK0hZX2AuVAPBLby1OjvmXqwImUQID\n" +
                "AQABoIIBGjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
                "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
                "bC5leGUwUgYJKoZIhvcNAQkOMUUwQzAOBgNVHQ8BAf8EBAMCB4AwEgYDVR0RAQH/\n" +
                "BAgwBocErBAAATAdBgNVHQ4EFgQUynSs9RAoplZqmr4uP3BKf+50qEwwZgYKKwYB\n" +
                "BAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBh\n" +
                "AHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcgMB\n" +
                "ADANBgkqhkiG9w0BAQsFAAOCAQEAFyj/YGtMuPT4oHfHw+mM4h83qM1kHSj6SFGe\n" +
                "BtLgX0XnC6k1oFsRk7eiQ4Lf4d6FKJhGVE+STkqPk1Mxfj5GPV34kXp8PXwQUPjw\n" +
                "PB9HosGZWRgPH03kkCvq/mvmzKSk3fkwMfhHJABLlQYlbEx0ZFpgfU7atNjshLOz\n" +
                "uwzV7kNpXL3xLjI/kIgCzr2UMSfNlF+Gv5qwT/RDzNSr+F3GIFNfx7PJmP/M/lNa\n" +
                "5MW7LkWEOpJFAGxW4g2ssGITQXHCvfcL0sIp4o1KzUMiXwgaMrdtj0ON3s5iqtVS\n" +
                "zplTRSF8Tgfw0i/iblG5Ap4RhcD5wsvLYF1VeTsWKmt2hhNzyA==\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Deny_ipAddress_forbidden()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // ipAddress=192.168.0.1,192.168.123.1 (the latter is blacklisted)
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDhzCCAm8CAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs4uQyl+JHKtQuADVbbtpw3g8\n" +
                "W9obkgaQWXiQA5k9mM3zJnUJa9HXfLGAy3x1X5biu6/8F8JdzMOETfLCH7lmNIxq\n" +
                "qWP94UgbE2C5+LcZaWG9C/ne59icLdX1gnrwwNbRYpAkq46f6z9pViyYpuJCBmXn\n" +
                "NkTbhsONLHPCwvLyYEG9cW31mPh3YQ/rEnAoB7BWiPByJPu26GZdo7NcJs+ZvehV\n" +
                "+uBPH8kL7/M5KAQdplKFlCbZvaGZSOBXNX6EAqkG1kbCSoQDUCe8tL0XXSiqf4l8\n" +
                "40IZ44xn+TeuhmczE6jyXxvOOyQipqS+eiV4/4+R7E5Mg58EUvRIg+aXgy7wcQID\n" +
                "AQABoIIBIDAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
                "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
                "bC5leGUwWAYJKoZIhvcNAQkOMUswSTAOBgNVHQ8BAf8EBAMCB4AwGAYDVR0RAQH/\n" +
                "BA4wDIcEwKgAAYcEwKh7ATAdBgNVHQ4EFgQU7yUp75Tjkkw9vuMo3ARZRlURr4gw\n" +
                "ZgYKKwYBBAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBm\n" +
                "AHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBk\n" +
                "AGUAcgMBADANBgkqhkiG9w0BAQsFAAOCAQEABSTtKWbLXwn9PGmPYQhSNgR1c4xJ\n" +
                "7AvqivmLbUspCIxzgCGx2gKsglME0D8OUr94bgRXCecVEA92o4Ev9AR0pCPF2jx6\n" +
                "6l+GpK1sjf2hrqU+Gp/MmJd7dvZk/L1co97oFNgC/3H66Mv0A/ohtGY0W01/MSnB\n" +
                "x5vdsf6apO5Gnvq+PdDGCb1qTFvjgZzvpALWOY2835k8PIY3CndBh7Ov/XZ2Tvr/\n" +
                "nY1BCWuu0d50Qm8hhVYOoVKP15vvqcr/UD2nlUY9Gv9kuScmmPi3q5QeK01kI4EV\n" +
                "bgfsnA7boakcA8eeKvCSXfdRdHrRFhSECwFLp7yu/m90XE9FIOYIzBVZeQ==\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Deny_dnsName_too_often()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // dnsName=web1.adcslabor.de,web2.adcslabor.de,web3.adcslabor.de,web4.adcslabor.de,web5.adcslabor.de,web6.adcslabor.de,web7.adcslabor.de,web8.adcslabor.de,web9.adcslabor.de,web10.adcslabor.de,web11.adcslabor.de
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIEVzCCAz8CAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzG+t/h3Ah19iL5Jv58Psr0EX\n" +
                "vV5nxtdKdBdpU7Yin0ya/etDFXX9tkg8HHk07OcWdYvqwtifxHCNI1Jf4Z/+e6Va\n" +
                "S+cQniOMszYoF07+JbqcFJv2aZVnKZSIJUH1qzyd5KR/mNCzFIFUqxEdZusr4yS+\n" +
                "rSlVCqD55YIbF/wlpWdEucLVx6g0DdQdZkaArQTr8WeuLNrEPCSl7I0ERr7GciWn\n" +
                "Z0boJysodza9t6d3JnfES62EQzRsYTw9qJaEwo4gdyNMZgYAT1xjImNhKeZywn9L\n" +
                "auKM72VwyTQEEkkDaQcpCS1u9iq53y4eYnGuJsXMG7DSPnz3C6O/msriuOQtxQID\n" +
                "AQABoIIB8DAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
                "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
                "bC5leGUwZgYKKwYBBAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAg\n" +
                "AFMAbwBmAHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBv\n" +
                "AHYAaQBkAGUAcgMBADCCASYGCSqGSIb3DQEJDjGCARcwggETMA4GA1UdDwEB/wQE\n" +
                "AwIHgDCB4QYDVR0RAQH/BIHWMIHTghF3ZWIxLmFkY3NsYWJvci5kZYIRd2ViMi5h\n" +
                "ZGNzbGFib3IuZGWCEXdlYjMuYWRjc2xhYm9yLmRlghF3ZWI0LmFkY3NsYWJvci5k\n" +
                "ZYIRd2ViNS5hZGNzbGFib3IuZGWCEXdlYjYuYWRjc2xhYm9yLmRlghF3ZWI3LmFk\n" +
                "Y3NsYWJvci5kZYIRd2ViOC5hZGNzbGFib3IuZGWCEXdlYjkuYWRjc2xhYm9yLmRl\n" +
                "ghJ3ZWIxMC5hZGNzbGFib3IuZGWCEndlYjExLmFkY3NsYWJvci5kZTAdBgNVHQ4E\n" +
                "FgQUXGUqf/a7LAB9cGx2EL/kKDfabXQwDQYJKoZIhvcNAQELBQADggEBABiXYOA5\n" +
                "F3imZ1jlmI3HlCiYBU6rDXn70MygPdszcIVmXAksCuADdLQcWZb8AeG3ywmbNFgu\n" +
                "x+HJWMpDrxTbPaKf/1Svk18pT329W5nppjxy3AGaUW6Bx8Yqnrw03u36oSM44pKg\n" +
                "tyl9hTzl/8+YvYzLl4tAvXKPMhtUI6rQZ3tRRak01xKchlMgEknEDMx6gHZ3zaRS\n" +
                "KqlX2MaUSzrffubkUdccoMrDsZgIEj541H1/3VbbkNDrQfgAuxrk0ivgkFXOI02L\n" +
                "v4eWHL0lwaS5Bk08EwHFj2FLuzCeHF15UbmaDQzJ9wj43Cn7+H82X3QQ+v0TDXPr\n" +
                "C6bmuhV2Gm14AnY=\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Deny_dnsName_forbidden()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // dnsName=web1.adcslabor.de,web2.adcslabor.de,web3.adcslabor.de,web4.adcslabor.de,web5.adcslabor.de,web6.adcslabor.de,web7.pkilabor.de,web8.adcslabor.de,web9.adcslabor.de,web10.adcslabor.de
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIFQTCCA6kCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArXgJYDmOKoK+GJ5AhPzYqBgi\n" +
                "ROXPhhxnriC/ImMF+FrQeTwAyVPS5zEAtuxYxFR9Kg/W7ob0qW6zoyKWkNxjzimp\n" +
                "DrJGX2M/g8PSyNnbExFFz6FiSZu0hM976oWRdzO3bBDyaWnuef8SM0YS9EWAzhOd\n" +
                "Yi16eboyRdAmi2nbwpVSG+idAz4R5LNAyGvl71PHHE0U+T3SccZdY81grGENXtNO\n" +
                "UOZ8Mb+5b5tNZLxIPsBdR24bvu3eNjQQmfzJcTjab0In091QRagX3cV7XOWN7C3f\n" +
                "kL0g0PePwJ3ILI6olqS1FpCKGb3PDKW/MCI/ekzBUItA+n4Kp+T+fZK//OmKBJpK\n" +
                "XI+bUjSKBcJIeAyvziceD/SgjQwRrH17L9ETcaM1Vs22cKLmdFrl0bCi8EEfyzzr\n" +
                "vBCJUKB9zEUYp5oK2kUmQIq+HBeLA1lyPz52fVb2+SeX0BWl6D6VZzf+mNdrDRq2\n" +
                "mMHzjBoU0wbLMtYVX8bH7c573aq2rLTWw4ILvtFdAgMBAAGgggHaMBwGCisGAQQB\n" +
                "gjcNAgMxDhYMMTAuMC4xOTA0NC4yMD4GCSsGAQQBgjcVFDExMC8CAQUMCkxBUFRP\n" +
                "UC1VV0UMDkxBUFRPUC1VV0VcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3\n" +
                "DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBl\n" +
                "ACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMIIB\n" +
                "EAYJKoZIhvcNAQkOMYIBATCB/jAOBgNVHQ8BAf8EBAMCB4AwgcwGA1UdEQEB/wSB\n" +
                "wTCBvoIRd2ViMS5hZGNzbGFib3IuZGWCEXdlYjIuYWRjc2xhYm9yLmRlghF3ZWIz\n" +
                "LmFkY3NsYWJvci5kZYIRd2ViNC5hZGNzbGFib3IuZGWCEXdlYjUuYWRjc2xhYm9y\n" +
                "LmRlghF3ZWI2LmFkY3NsYWJvci5kZYIQd2ViNy5wa2lsYWJvci5kZYIRd2ViOC5h\n" +
                "ZGNzbGFib3IuZGWCEXdlYjkuYWRjc2xhYm9yLmRlghJ3ZWIxMC5hZGNzbGFib3Iu\n" +
                "ZGUwHQYDVR0OBBYEFLHzMISFNmmMU/xchafRVXOY1GnwMA0GCSqGSIb3DQEBCwUA\n" +
                "A4IBgQBAX2dAWlfNd+9KRS06QvNFLKfaRrRiYIPVVe5K+wevkgNquV5Sf6quVX64\n" +
                "xkHpAUU9GWB4CFrwXE0KbouBozLhKvamjg1Ndl7ZxGolnCGfPqReVVpKJ9WViGrY\n" +
                "SxqMMvX+jJY1L/Res5SwnboiNIRYS3z/hoQiMs9dqvzR1gs92ygIHxhDNroYd1O8\n" +
                "9gIZ7TGnV07r4WWut6GLA9ljDPPsx6nj1kOB4yQFNHCfrrzcUXpThXdhL1nrOIJY\n" +
                "2px38RuAPHh47AKP17uTwEvkdIX5hh0g8mEdyTqzoTpJfkl49Q4eCRWhJYvSvWqm\n" +
                "vWvQWzxyN7rFyonbOya6uU8M4uhLm4hKkfscC4KUtukfIli3X6KxPupEEmbFUXZZ\n" +
                "2GZLqPeJ1xiOtsglTQ+uYNvwelQk+B8fPgX0ouvduEeJldQ48I8+T4Ni9wUmtm9H\n" +
                "B5takWnKYdzvkFi5cEPGpK+Qe08vN5Lg7w9QK0/8vJfk6hvc/mk2qnECvOsJQuug\n" +
                "gIECro4=\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Deny_empty_commonName()
        {
            // 2048 Bit RSA Key
            // CN=
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDXDCCAkQCAQAwCzEJMAcGA1UEAxMAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                "MIIBCgKCAQEA6c+ekUJOIzXi+pUk1yJlPQ3YAvJ4Pd+XC2XO6N+djh6NZBo6Vfch\n" +
                "YlSwZBVOuvIBWAo1UGS4WHhcPhyc1V5mTV+xIBdE2FAGU7/tmP8OorSwrK0uWnlm\n" +
                "xh4bqM7oNNTp1hqClrsu8HlA0JexjY8nCFm1o3ZVlc1UkOtHgddBqOeBmoLP6t58\n" +
                "6/qpp7/0xKn8Gyy0llarSEjzb4Q1WF/yTcQWQs0FGnTosiOeZjFwPtJy5a3QNm0N\n" +
                "ca3yxi98bRCDpVLrzw/vmoQfN6J+X4+jH/puu7T41Vpcn3KRO7hg1Joj3VzmFM6K\n" +
                "xXj2Fn4oMTOsVf30gUxWFPjRdHOWyn5ysQIDAQABoIIBCjAcBgorBgEEAYI3DQID\n" +
                "MQ4WDDEwLjAuMTkwNDMuMjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIH\n" +
                "gDAdBgNVHQ4EFgQUC2bPM5AoVdXCppGhooPAw12j8NAwQgYJKwYBBAGCNxUUMTUw\n" +
                "MwIBBQwKQldQLTIzMkM0NAwSQktVXFV3ZUdyYWRlbmVnZ2VyDA5wb3dlcnNoZWxs\n" +
                "LmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAA\n" +
                "UwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8A\n" +
                "dgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBAQA7dExmjDRsIAs6O6JwDkXP\n" +
                "ZAdv5qNyEO1TjQ8EDUl3hWhrjo2LdiX29/Apd7MvHf+OmTWNfvOHMy1R7uByhkSb\n" +
                "TINgpbHkT8zq9DY8rhV0Hk1CqEGqx9VZ6fJ8fElKXhmq4UYc2DwWgppmnofwnC5n\n" +
                "HAMpHLzOlcL49XYG3l/yBVrRKFhPJ+7wXrsxF0Kt8TFbQyQvzlBrn9J3He/toTnR\n" +
                "Gi5zMH4MtdDvb8lf64R9BVd/r9EQEKXOsDG2XG3X9oHpSrb9yQ4bnaimOW+qhzgS\n" +
                "Qbc+EMH4FY4v2YSfjsI3Lwqc5D/VUjjiurH09jtUokXLJme98UiwpFbBu2JDi2T/\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Deny_no_subject_DN()
        {
            // 2048 Bit RSA Key
            // Subject DN is empty
            const string request =
                "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "MIICRTCCAS0CAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN3I\n" +
                "pfU4s5WnSooZ5YXS/KM567BOo+kPIht61hgDYV1dKJw6monu3G9CZEbmKZROGaD6\n" +
                "Wgwrq0G0Tdumi4JDuV0N/mo1E+YYGHV0mJn3a6LRoOtpGtnXfXyfJTrvUqS8ojIr\n" +
                "VbKnF3DYVZUbzMbUXeNYvvhdZqbv+F777GAaRLPeMxQfwrx/jHq/sBobNZsMP55W\n" +
                "1BBbdXnDuFZ3vOKYuP0TnJnTt0AQvcAKod+BSZhhJ+LacXwuClGBv/hXE61ec/NE\n" +
                "UfkBfjhYMRnklVxNYVfKPRVOZHQeMICwN/LzYdXd2z8E/Y1buFOt9fppVft4rxK/\n" +
                "tvdcyasTSbyMMNqW8Y8CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBwWbeu6pcv\n" +
                "1ma3WcxuZRjhAXLZFYO5S8MTAA5DuMAVQiWYCkViSdzwijTzy0ngb+tk/Jq4bIcu\n" +
                "Kv6dyTVBkshjOkhdFNqov98iruK4VDf6SLy55mlSpppBXXSq2iGmkurbTRPSc6vg\n" +
                "FqsZo1Yk9fevYBTv68oy5r9JXpQv6mwZFCWWkpG+5/2sJ7g0Z2Tlus08yB6gMYej\n" +
                "mNFV86EtLaT8MUNLYWdNeTSIUo5ywnnKPQNRCJFOGxxDrtaEk6THyhfq6JdeMrX3\n" +
                "kTnibd+tk1uev4YvxMh1Vh3E/H08REe+oXSIS380agnNR8bbPm9uXXoRFoBSzWdA\n" +
                "UuB3ABtxKzki\n" +
                "-----END CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Deny_countryName_invalid()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de,C=UK,O=ADCS Labor,L=Munich
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDoDCCAogCAQAwUzEPMA0GA1UEBxMGTXVuaWNoMRMwEQYDVQQKEwpBRENTIExh\n" +
                "Ym9yMQswCQYDVQQGEwJVSzEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRl\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0YUGDn2SUYfGtCvbw7o5\n" +
                "jNzyAAafFxggO56A8xDgjoVqFm/6/L3gC6LWYonCm+7Od3LucQQ/T5pN3n7YQuoM\n" +
                "5DMq0H0W28mYiLPV1M8bOWjK1yVjCpsnShRSQLSThzG+oJS2GNmLVAIT4MvGLB8j\n" +
                "lYhoxVoTEFJe9DIokx+ND8B+rzY61oiczI84JMd0wmRUh7vmxiLDH105DPbk9JQu\n" +
                "vBi65T55UK/8FiyfI+n/f9vIUzRg7A3y3MmuIvRsLwQqCGebPcQynJb4ctvyEusy\n" +
                "qcr7RjNMEvXU2jTyg3OQ95YKKFDm1e8KWuXAQovbVsCQzZSyGrbreMjY3W5JjDZ2\n" +
                "dQIDAQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkqhkiG\n" +
                "9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU5jHx96HaHlJuMfEr\n" +
                "wIRY/JzsDWgwPgYJKwYBBAGCNxUUMTEwLwIBBQwKb3R0aS1vdHRlbAwOT1RUSS1P\n" +
                "VFRFTFx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcNAgIxWDBWAgEAHk4A\n" +
                "TQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMA\n" +
                "dABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJKoZIhvcNAQELBQAD\n" +
                "ggEBAHF9KEclG5CQX+okcw0AcjTAeYHNMp6RLDdwyLOqShWubNzVeOl31ABYoASD\n" +
                "/9qpFR7qsodCjDOZLIiE6BEIxbPOGMTrZ0FbgHnexkyreGpfAm0f7jJzm+6iA/os\n" +
                "iHFA48DS5CMZd1LKvm3IP0bvGTVoYS0bRWWBSP67eiL9irpzApMgvCfRTJj6qqzp\n" +
                "htlXTjgOxTYT7DC1y4oXnfUoQypdASDNiUBVBcEPC6wOWWCLwzdJdk/kSenYeJl0\n" +
                "soDwHamNh0o+tmOdX2Wuyxh35vSMUaLztjNDU0kjXadEJFogdvfzv7X5+/w/KQlx\n" +
                "iddTemRyEEPZ3Xk6Apfthttqzwc=\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Deny_givenName_not_defined()
        {
            // 2048 Bit RSA Key
            // "CN=intranet.adcslabor.de,G=Test"
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDfDCCAmQCAQAwLzENMAsGA1UEKhMEVGVzdDEeMBwGA1UEAxMVaW50cmFuZXQu\n" +
                "YWRjc2xhYm9yLmRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt8F0\n" +
                "S+emD/3rWYUF7OSTx9httguDLf7IQd1uvVfsBdIk1kyf/MEmfPHHOs/Is8bLsz6y\n" +
                "yWtraHjv1QqUMy9nOlIdwP/MJV+rc2MAcWoupB4xUgfoS1Rixmc9VRKUDzLw1PWn\n" +
                "S14QzUu8Zd+oR370doMhGZlL4R59aXp/jBa/cxX2DGAZgBkQQzYejgEbWSh44Cs/\n" +
                "gVIqjKCJgra6zAXXoq2OT0uW0HjWCADHvl3yvN04wbakvNDhipUSAGBrGivHlCm1\n" +
                "xpVXNBpjo3Lfl6r9peXKufwwAAo6WaQURClD5Uy1fmuAH75YVZedwTyfpDQdlnAR\n" +
                "rUuSzr/T7uHcirgIuQIDAQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkw\n" +
                "NDQuMjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU\n" +
                "LzwfyiOg/meb9cnbM6hUMh0zA+wwPgYJKwYBBAGCNxUUMTEwLwIBBQwKb3R0aS1v\n" +
                "dHRlbAwOT1RUSS1PVFRFTFx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcN\n" +
                "AgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUA\n" +
                "IABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJ\n" +
                "KoZIhvcNAQELBQADggEBAJir0lIk5w2uESofvvYDp9QOj0/aEHL2bVLup7s2al0o\n" +
                "TNy/UJ/YQTckPXRr4J2kVUxH9HLo97V5qYOQ1J082MIckjJjdYRsSVh6VTJ5njTY\n" +
                "4p5olpbegQyfJzFPz3L2ktk1fetuFck0NtM9cMVMpVnXrA17/LS7Rvn5aXnRKYNK\n" +
                "KP3NjtTf9g+a/CVJ0NYo9R5XL4kf/vIQkl7PYRy/FAi2ASrDb1woLUOBh4rBFH+s\n" +
                "PRIbFsXr7BdWMDKM92zH8bUCrPvNuN+hjdLrgREdONYf52UdZRt/nwShKkMHVxDW\n" +
                "f482T7HTzF4MuKb/m+x7nUz1eMFHXTy7TFoaYRxv3V0=\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Allow_process_name_valid()
        {
            var requestPolicy = _requestPolicy;
            requestPolicy.AllowedProcesses.Add("powershell.exe");

            var validationResult = _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Allow_process_name_invalid_in_audit_mode()
        {
            var requestPolicy = _requestPolicy;
            requestPolicy.AuditOnly = true;
            requestPolicy.AllowedProcesses.Add("taskhostw.exe");

            var validationResult = _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.AuditOnly);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_process_name_invalid()
        {
            var requestPolicy = _requestPolicy;
            requestPolicy.AllowedProcesses.Add("taskhostw.exe");

            var validationResult = _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_process_name_unknown()
        {
            // 2048 Bit RSA Key
            // CN=somewebsite.intra.adcslabor.de
            // no process information
            const string request =
                "-----BEGIN CERTIFICATE REQUEST-----" +
                "MIIC8zCCAdsCAQAwKTEnMCUGA1UEAwwec29tZXdlYnNpdGUuaW50cmEuYWRjc2xh" +
                "Ym9yLmRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3cil9TizladK" +
                "ihnlhdL8oznrsE6j6Q8iG3rWGANhXV0onDqaie7cb0JkRuYplE4ZoPpaDCurQbRN" +
                "26aLgkO5XQ3+ajUT5hgYdXSYmfdrotGg62ka2dd9fJ8lOu9SpLyiMitVsqcXcNhV" +
                "lRvMxtRd41i++F1mpu/4XvvsYBpEs94zFB/CvH+Mer+wGhs1mww/nlbUEFt1ecO4" +
                "Vne84pi4/ROcmdO3QBC9wAqh34FJmGEn4tpxfC4KUYG/+FcTrV5z80RR+QF+OFgx" +
                "GeSVXE1hV8o9FU5kdB4wgLA38vNh1d3bPwT9jVu4U631+mlV+3ivEr+291zJqxNJ" +
                "vIww2pbxjwIDAQABoIGEMIGBBgkqhkiG9w0BCQ4xdDByMA4GA1UdDwEB/wQEAwIH" +
                "gDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUEskQwgjBJxMXqii7Ox3F" +
                "TfTQHF0wLAYDVR0RAQH/BCIwIIIec29tZXdlYnNpdGUuaW50cmEuYWRjc2xhYm9y" +
                "LmRlMA0GCSqGSIb3DQEBBQUAA4IBAQDIQrqmM0q8jnquRWV136E+tQxF6VFcBu3R" +
                "AraAkyZ+Aw8NVrRXzyBCL+hupW9zPF9B6xHNfyCbxX5Kqf2Ur5+FuemmzYkBAsHw" +
                "L2jbj0KymYwv+31AMubLZHO3oyq/GuJkP6VnBm7JpI5kSncU9zA2Sq/lgiUk+wg+" +
                "FGHD3m/c8eUDUJCWM79W2buAgG0EAU/a96gPvcHUq2d5eFduLYOzLb5BA20g7hit" +
                "fYRvkB/pz1QtanK+I4vEEb/wMj6Dj6Tyo4JsSqts5bSS1uFkPsKtzmA4bdqxml2f" +
                "s4Exo9Lmx0bAKHD3xMUX19RukXDpM6ssBGe71LGqaAAfNH40WHBO" +
                "-----END CERTIFICATE REQUEST-----";

            var requestPolicy = _requestPolicy;
            requestPolicy.AllowedProcesses.Add("taskhostw.exe");

            var validationResult = _requestValidator.VerifyRequest(request, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_process_name_forbidden()
        {
            var requestPolicy = _requestPolicy;
            requestPolicy.DisallowedProcesses.Add("powershell.exe");

            var validationResult = _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Allow_crypto_provider_valid()
        {
            var requestPolicy = _requestPolicy;
            requestPolicy.AllowedCryptoProviders.Add("Microsoft Software Key Storage Provider");

            var requestAttributes = new Dictionary<string, string>();
            requestAttributes.Add("RequestCSPProvider", "Microsoft Software Key Storage Provider");

            var validationResult =
                _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo, requestAttributes);
            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Deny_crypto_provider_invalid()
        {
            var requestPolicy = _requestPolicy;
            requestPolicy.AllowedCryptoProviders.Add("Microsoft Platform Crypto Provider");

            var requestAttributes = new Dictionary<string, string>();
            requestAttributes.Add("RequestCSPProvider", "Microsoft Software Key Storage Provider");

            var validationResult =
                _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo, requestAttributes);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_crypto_provider_unknown()
        {
            var requestPolicy = _requestPolicy;
            requestPolicy.AllowedCryptoProviders.Add("Microsoft Platform Crypto Provider");

            var validationResult =
                _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_crypto_provider_forbidden()
        {
            var requestPolicy = _requestPolicy;
            requestPolicy.DisallowedCryptoProviders.Add("Microsoft Software Key Storage Provider");

            var requestAttributes = new Dictionary<string, string>();
            requestAttributes.Add("RequestCSPProvider", "Microsoft Software Key Storage Provider");

            var validationResult =
                _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo, requestAttributes);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_commonName_too_long()
        {
            var requestPolicy = _requestPolicy;

            requestPolicy.Subject.Clear();

            requestPolicy.Subject.Add(
                new SubjectRule
                {
                    Field = "commonName",
                    Mandatory = true,
                    MaxLength = 4,
                    Patterns = new List<Pattern>
                    {
                        new Pattern {Expression = @"^[-_a-zA-Z0-9]*\.adcslabor\.de$"}
                    }
                }
            );

            var validationResult = _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Deny_policy_pattern_expression_invalid()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // ipAddress=192.168.0.1
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDgTCCAmkCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAssXMb23gWNQPuO2OtHubWSIH\n" +
                "f05rvRfHr4pRmMoI3JFuwnTHs5ho3sLtLu/NOroH5xUAthC/OJoUFOusu/9vlptf\n" +
                "8oPABXvHRCuCsEhdfGB/+p7Wf/FMm+YU9KhwNUM1kt1wQ2XAFKEi11iaF8YkzyQ1\n" +
                "PP8zqRU0UNEXlF1GWgc1DOnOkKKkZS2jE1LQ6yBm+suD++EMGPUH+7OSNDGvtWEM\n" +
                "D9LMhH+vcdYpABJbz7jzjytIXmayEQM4oz8CT/2NfRMzSeMOheDCILJugK43A+qe\n" +
                "BpTfie0LA99vYFIHe4vh7Mxc+FR+aHL3dP3doQnt98a0R14XnNn/uUadA46C2QID\n" +
                "AQABoIIBGjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
                "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
                "bC5leGUwUgYJKoZIhvcNAQkOMUUwQzAOBgNVHQ8BAf8EBAMCB4AwEgYDVR0RAQH/\n" +
                "BAgwBocEwKgAATAdBgNVHQ4EFgQUhkzXt+AAu7HigUpHv45MuccLo/IwZgYKKwYB\n" +
                "BAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBh\n" +
                "AHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcgMB\n" +
                "ADANBgkqhkiG9w0BAQsFAAOCAQEAb0k413f2rAuTtb3cmS3e0w2jLR71d8+OZZ4w\n" +
                "HN618i5xc/1boSY7p/M5rWRbZp4xdtpwYtUFOsUxuOrZdTjYckY6i834r9xZ9BCP\n" +
                "cw3V0FISgyZ1g5lIkV1rQW2V66ZA3SVyzXoPQQ0AJBMdiudIbFsg1BJ3LwmIjuGS\n" +
                "4TF3unbiVDFNXchtwICznn2OFPWPeGnz37xRiuWK7rheXOU+KHWHaVUpyar8J+5O\n" +
                "RRsjitR+Lgqvm/KYUacA5TARMVhGjPzS4O42VYCGjlMR74YaQi+LH3Vezft5G/Ft\n" +
                "CpV76XuDMJqMk4VrPkh1rLljbGqKzuQzIuCVAPFBhsLCqnHByQ==\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var requestPolicy = _requestPolicy;

            requestPolicy.SubjectAlternativeName.Clear();

            requestPolicy.SubjectAlternativeName.Add(
                new SubjectRule
                {
                    Field = "iPAddress",
                    MaxOccurrences = 10,
                    MaxLength = 64,
                    Patterns = new List<Pattern>
                    {
                        new Pattern {Expression = @"thisIsNotACidrMask", TreatAs = "Cidr"}
                    }
                }
            );

            var validationResult = _requestValidator.VerifyRequest(request, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Deny_policy_pattern_empty()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // ipAddress=192.168.0.1
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDgTCCAmkCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAssXMb23gWNQPuO2OtHubWSIH\n" +
                "f05rvRfHr4pRmMoI3JFuwnTHs5ho3sLtLu/NOroH5xUAthC/OJoUFOusu/9vlptf\n" +
                "8oPABXvHRCuCsEhdfGB/+p7Wf/FMm+YU9KhwNUM1kt1wQ2XAFKEi11iaF8YkzyQ1\n" +
                "PP8zqRU0UNEXlF1GWgc1DOnOkKKkZS2jE1LQ6yBm+suD++EMGPUH+7OSNDGvtWEM\n" +
                "D9LMhH+vcdYpABJbz7jzjytIXmayEQM4oz8CT/2NfRMzSeMOheDCILJugK43A+qe\n" +
                "BpTfie0LA99vYFIHe4vh7Mxc+FR+aHL3dP3doQnt98a0R14XnNn/uUadA46C2QID\n" +
                "AQABoIIBGjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
                "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
                "bC5leGUwUgYJKoZIhvcNAQkOMUUwQzAOBgNVHQ8BAf8EBAMCB4AwEgYDVR0RAQH/\n" +
                "BAgwBocEwKgAATAdBgNVHQ4EFgQUhkzXt+AAu7HigUpHv45MuccLo/IwZgYKKwYB\n" +
                "BAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBh\n" +
                "AHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcgMB\n" +
                "ADANBgkqhkiG9w0BAQsFAAOCAQEAb0k413f2rAuTtb3cmS3e0w2jLR71d8+OZZ4w\n" +
                "HN618i5xc/1boSY7p/M5rWRbZp4xdtpwYtUFOsUxuOrZdTjYckY6i834r9xZ9BCP\n" +
                "cw3V0FISgyZ1g5lIkV1rQW2V66ZA3SVyzXoPQQ0AJBMdiudIbFsg1BJ3LwmIjuGS\n" +
                "4TF3unbiVDFNXchtwICznn2OFPWPeGnz37xRiuWK7rheXOU+KHWHaVUpyar8J+5O\n" +
                "RRsjitR+Lgqvm/KYUacA5TARMVhGjPzS4O42VYCGjlMR74YaQi+LH3Vezft5G/Ft\n" +
                "CpV76XuDMJqMk4VrPkh1rLljbGqKzuQzIuCVAPFBhsLCqnHByQ==\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var requestPolicy = _requestPolicy;

            requestPolicy.SubjectAlternativeName.Clear();

            requestPolicy.SubjectAlternativeName.Add(
                new SubjectRule
                {
                    Field = "iPAddress",
                    MaxOccurrences = 10,
                    MaxLength = 64,
                    Patterns = new List<Pattern>()
                }
            );

            var validationResult = _requestValidator.VerifyRequest(request, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Deny_sid_extension_forbidden()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // sid=S-1-5-21-1381186052-4247692386-135928078-500
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----" +
                "MIIEvjCCAyYCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB" +
                "ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtpktqmDWCzarYusWvZ/O0/AC" +
                "i6hVnBR6tzUCeWcLA6qmznWSqdDym0yVndHRTCqYiZgvgfMBKRr9nTQPzLMM3k+5" +
                "BfuEFTgCCvlmlRxSLuDenI4w3CIGLDkRxv/pAZO2VeIdYAsfGm79QV5/tU6UZ3ZN" +
                "G4ix5bb7udfJOdBN576Q2qtte1BnMqzzwJB8fH8Jc/MOx75flx/e+2AmZbeIDtxD" +
                "j2MDG+kQ3t+PFfws8LSAy5q/CHUVlkoSb0BT0U/X1UBcQQriSVqofK9JDB1Ok5XU" +
                "QdsBKdZGyeChRUrS10iEgTWpawrfvt2MbObwhpHrV/WDdVmEif4t5PKWqgFahHZT" +
                "tWt1r4JGMxRLHfAGnjOt2k14JpOpqMAgkHPLGPXJsmlD4un8enrx5QU156CwAHLg" +
                "6ltkDi+sgkeWhMMok4fb21uzKouclacE2vR+l/F8LUP52AeBsQAmRucyJkXbM0QY" +
                "eR9w9Cu2RT93s+DFPTtE1U3093StXhLY5GzsG2rdAgMBAAGgggFXMBwGCisGAQQB" +
                "gjcNAgMxDhYMMTAuMC4xOTA0NC4yMD4GCSsGAQQBgjcVFDExMC8CAQUMCkxBUFRP" +
                "UC1VV0UMDkxBUFRPUC1VV0VcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3" +
                "DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBl" +
                "ACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMIGO" +
                "BgkqhkiG9w0BCQ4xgYAwfjAOBgNVHQ8BAf8EBAMCB4AwTQYJKwYBBAGCNxkCBEAw" +
                "PqA8BgorBgEEAYI3GQIBoC4ELFMtMS01LTIxLTEzODExODYwNTItNDI0NzY5MjM4" +
                "Ni0xMzU5MjgwNzgtNTAwMB0GA1UdDgQWBBRIW5wIKxgYQ54ZqtEnPJb1up2dHzAN" +
                "BgkqhkiG9w0BAQsFAAOCAYEAV9BiaDSo495k4WccuFVRoXpxfl46NuZA7WBL/7F5" +
                "smqmslc5pVnXWf6HLigoEJIKBmZ1ro4FvL73o9cX0sL4xx3b8DO0GSQ7DsB5fLy4" +
                "Rm3pynkpIblbwDLcHfZGCsY1ZOOuBLXpDyBhqWv37iDKcErtRR/guoLEWScUAfWr" +
                "LAAXuDkJF7pOAQNytUDGG+Gk6GILvGs1TiDYtFdM9K4A1uyjnhcU3fv3uLXC3mdZ" +
                "S1PA/8sO7ItSJyf/CgDsJZnZ2/WNdAq05po0ELjmte3o/n+8avAXqot8XjC+Jm1n" +
                "xieO9UfUwubES3b2S1GLpFdW20fsVsjhyI76nOPqDDRXhqksiIEMDi0S1QjQyUbR" +
                "smdERk7+lImY1iOfJH3ZrG+cpEEMDZCNpvxSn9rgq8CbIR4v0K6SG4PlX4bUIpV7" +
                "giA5RXlS0BWKeT4g+7p35hAqf/NFAJ3HP0tIkY7TBKOB4nhRUixaJPUFTvnZZCT6" +
                "FruEf1rk3/tB/ywnVKL9KRsn" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.NTE_FAIL));
        }

        [TestMethod]
        public void Deny_commonName_invalid_dnsName_invalid_PKCS7_encoded()
        {
            // CN=this-is-a-test
            // dnsName=this-is-a-test
            const string request =
                "-----BEGIN PKCS #7 SIGNED DATA-----\n" +
                "MIINmAYJKoZIhvcNAQcCoIINiTCCDYUCAQExDzANBglghkgBZQMEAgEFADCCBKcG\n" +
                "CSqGSIb3DQEHAaCCBJgEggSUMIIEkDCCAvgCAQAwGTEXMBUGA1UEAxMOdGhpcy1p\n" +
                "cy1hLXRlc3QwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDrj8b+p7kZ\n" +
                "TBC9qNsTy/WUz15ZP9r2my4q0h3SqJHcWOMsw+rVn71hktdF0h7qJ01NpYj36h8P\n" +
                "/lJx+5n3ELqRmQmWuoT/pyv2JNpIr85DFHrOhyLnbeTmoPCffxbC13Htc5MsiNkw\n" +
                "zjJKccEIpThswSsv4Sb5rVpMTnI6hax00SbKOuvbLxgMlCk6XYFbLl17bjhs3S76\n" +
                "QHet6fzSjs6pweHpzvXVkSqT7SfBNcUjiKxE6kZdPq/i1H/UxpFmicl1QdKe41ng\n" +
                "CkHC++Exyd9Q6LpOItxwcyaGnjFjTEKhEcFafPESoiz4UhQe9cvezVA0GGkfMLIV\n" +
                "IHU8Oquo/CLfHypD7Zo3lidj7BLkNoJ2wjqYhyTN5bGMF8TjJwIuVCdSrxsy5PO/\n" +
                "1KhQlq8o15wZH87uq2RDmHwaPrUNnUvc+HDzBRK4zQRBgJkNgFMKmAzcg/lMZIjI\n" +
                "LubTYAUUxV+s1zayxX4AKUkOl0qwB408BlPR9AgonscyRgHZXoAC8BkCAwEAAaCC\n" +
                "ATAwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE4MzYzLjIwSgYJKwYBBAGCNxUUMT0w\n" +
                "OwIBBQwaQ0xJRU5UMi5pbnRyYS5hZGNzbGFib3IuZGUMCklOVFJBXHJ1ZGkMDnBv\n" +
                "d2Vyc2hlbGwuZXhlMFwGCSqGSIb3DQEJDjFPME0wDgYDVR0PAQH/BAQDAgeAMBwG\n" +
                "A1UdEQEB/wQSMBCCDnRoaXMtaXMtYS10ZXN0MB0GA1UdDgQWBBTGOY+4vRUIPXd/\n" +
                "VKw0lskOiBAsyDBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
                "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
                "UAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBgQDEXpI2qKbCcQNk\n" +
                "xFQ7zWIbpIEn1ZPYp4Yh1665KOR0AUXNNgD5DeuwOOv6TBZYhk2GG3NQbghCZRSU\n" +
                "W7ErrHciv4fIZn9lrvSvl8yeRCaZWe5Iq9Y/n8Mi+o30c5MRkpk2TpaXAWz91vbX\n" +
                "WkC6NctcazsbTg4O09pgZFwY1/+sjcwliCUYNfX2eIjrBqSDEzWFHRwXp0Nl8qLu\n" +
                "HDybDu8PJqRalGwjmHnbt5grqGpu7PLnpkGut71Jq5n+MM5k62E5tzDSA+6HEAUd\n" +
                "CL/uKS/fayVp7ZSAo93lXlml1o7CbEz7g7pIfMel+Pnrk3T6hFR/zbq8m+tlar4m\n" +
                "uohOBvnr5I3lDAGC4Yit/JEiZJRvT73ESEQvTZvlDSWyNt0sOOJEzYsGA2ASoINO\n" +
                "3ynSVhJCzeiwhT2p0X+2ghKY8hPhL5aFa6fxjqb/aj5gEk69eIfql3pzC3Bb6vbS\n" +
                "Ym9bWkxH134NkATEaweix9oKAjc/mDhJgE7w7oe4wTkSWIqMFougggcHMIIHAzCC\n" +
                "BOugAwIBAgITcwAIDlrU+8kfM1yNGQACAAgOWjANBgkqhkiG9w0BAQsFADB0MQsw\n" +
                "CQYDVQQGEwJERTEQMA4GA1UECBMHQmF2YXJpYTEPMA0GA1UEBxMGTXVuaWNoMRMw\n" +
                "EQYDVQQKEwpBRENTIExhYm9yMQswCQYDVQQLEwJJVDEgMB4GA1UEAxMXQURDUyBM\n" +
                "YWJvciBJc3N1aW5nIENBIDEwHhcNMjIwNTI3MTE0NTA2WhcNMjMwNTI3MTE0NTA2\n" +
                "WjAPMQ0wCwYDVQQDEwRydWRpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" +
                "AQEArAbgsEjyO5ntIYeXs03gYY7O36VwDTpXl/aZXnfYx/+0BnXc1jhR6ptj0T1J\n" +
                "BHsRk9jN1zjpmYqgPii2z09ngbcY8eiQMNvAgGurm/SW3JPzJyu9k0ymp8FL4AAQ\n" +
                "9WQL1uLDLfkq7AOna94Qw9m3Lj7NsqkH5Fz31Qv7C/ZYx0jUjA/g678pHHBc2lY7\n" +
                "dmL3abUwfweRxltZMkZDXSVnzwdywnUGIz1XsxETHnRnpDGgTKnn0wYix7zBFtNT\n" +
                "4mLczORoAoP8yrCDt64NsnFqGdaeltxTYEnTHZV5I30wI89YAnoH5y+wHL6OiNh7\n" +
                "qBjidq99QSFS0kBQBnvtHTDprQIDAQABo4IC8TCCAu0wOwYJKwYBBAGCNxUHBC4w\n" +
                "LAYkKwYBBAGCNxUIg4DSJ4GzrS+ZlxrppUGs9FSBZ4H8uW2EuYEfAgFlAgF4MB8G\n" +
                "A1UdJQQYMBYGCisGAQQBgjcUAgIGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIGwDAd\n" +
                "BgNVHQ4EFgQUFbhF8pcdgkFNlrTzwk+tHr/x2tQwHwYDVR0jBBgwFoAUPZPjtsSQ\n" +
                "Ro8fyiwzjNtRJPyH/XQwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDovL3BraS5hZGNz\n" +
                "bGFib3IuZGUvQ2VydERhdGEvQURDUyUyMExhYm9yJTIwSXNzdWluZyUyMENBJTIw\n" +
                "MSgxKS5jcmwwggFdBggrBgEFBQcBAQSCAU8wggFLMIHIBggrBgEFBQcwAoaBu2xk\n" +
                "YXA6Ly8vQ049QURDUyUyMExhYm9yJTIwSXNzdWluZyUyMENBJTIwMSxDTj1BSUEs\n" +
                "Q049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmln\n" +
                "dXJhdGlvbixEQz1pbnRyYSxEQz1hZGNzbGFib3IsREM9ZGU/Y0FDZXJ0aWZpY2F0\n" +
                "ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwUwYIKwYB\n" +
                "BQUHMAKGR2h0dHA6Ly9wa2kuYWRjc2xhYm9yLmRlL0NlcnREYXRhL0FEQ1MlMjBM\n" +
                "YWJvciUyMElzc3VpbmclMjBDQSUyMDEoMikuY3J0MCkGCCsGAQUFBzABhh1odHRw\n" +
                "Oi8vb2NzcC5hZGNzbGFib3IuZGUvb2NzcDAyBgNVHREEKzApoCcGCisGAQQBgjcU\n" +
                "AgOgGQwXcnVkaUBpbnRyYS5hZGNzbGFib3IuZGUwTgYJKwYBBAGCNxkCBEEwP6A9\n" +
                "BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTEzODExODYwNTItNDI0NzY5MjM4Ni0x\n" +
                "MzU5MjgwNzgtMTIyNTANBgkqhkiG9w0BAQsFAAOCAgEAdfez2lwMm1XLRG/K6inn\n" +
                "D38XXZqFN8JPHJk4wpVUIAuFHF7+FPRdJaDD/rfk651bDYrQnzwgXCXa0qqvS2oa\n" +
                "NE5dVU7ZUJxOAkjqLZOZPzgDWPfwtModlABHhviVlY2ydKLzSMJfgiItqDFjYk4n\n" +
                "IZlQyydpXZxf1jirdsATnInDuqS/5BJlMRYYeO7K7p7HqPFqwZ138OIXNmK9EBNo\n" +
                "8qJsgTE9qn29VJOKUnBuwyHhewRSOIgL5oJz7aHqNmQsVQSeUO7uN/LAbAfPNCgS\n" +
                "/V3LL9S4tHytYY0JhxsmRA1eKWtlNkZG7cKmhf2Dsl5XlrOgkqDwNyPjuSC+55Tp\n" +
                "5fUm+XCdxiRkHggl7KDZoQP0UTjBT0mgQyvwINPegfA2F157n2BwnDjaiFLv1u+H\n" +
                "bPPn7Yo1SICtxcPQv+J3cszcZl8T9aD0cXSd/s+9Noazy9ZriD5nrQG0uqJSCHUp\n" +
                "xO1iKP2smz5M4ByMrFI3ljbGpbfuS6blcVwNduxZpgTNLmj/rZk+B+frXfJxFL1k\n" +
                "TYJKA4GLLAUIOybPeydNDTHs+RlFQXT0WUg91TBtW2CnHQJKajw/EScWmVX9Az2f\n" +
                "XIL/KQnR9dBqGSyJ1ttOZ6DH8ybE7IusRjkJUjZdRLiwxsmDhzWd9nQEkedbrRUM\n" +
                "62tj3XcrgHpTt6ugnRxsj8cxggG3MIIBswIBATCBizB0MQswCQYDVQQGEwJERTEQ\n" +
                "MA4GA1UECBMHQmF2YXJpYTEPMA0GA1UEBxMGTXVuaWNoMRMwEQYDVQQKEwpBRENT\n" +
                "IExhYm9yMQswCQYDVQQLEwJJVDEgMB4GA1UEAxMXQURDUyBMYWJvciBJc3N1aW5n\n" +
                "IENBIDECE3MACA5a1PvJHzNcjRkAAgAIDlowDQYJYIZIAWUDBAIBBQAwDQYJKoZI\n" +
                "hvcNAQEBBQAEggEAlJVSq7hr7o17x8WavmELZoleLOYcaB3txm1+x27fakz9IlDg\n" +
                "zO3Re8WyXEwd44Ykjc5RtzGXlmBUBup7TrF84TodqZjmXjmY+tuvaboS76L5PhMq\n" +
                "VHbwcjWIdKRy/OMH00aMDLQyd2sC+xsIR4YqWA2fVBPHYZq4uZ4Qnfmg9A2NLDGM\n" +
                "xyAmX6eN2uC/jgMRaAbWrEI63R4nHBlZWBPel/GgwOc5HUc2vSCJzC1QrD/tRvuz\n" +
                "p7wxv0zUScBB8ZrMfTP9miCcnL/k3t6LKscION3KB9aqjlU4DZDZQ2eopQKkFqHJ\n" +
                "ivMQZOGuu4Ri/tn7IY5KGOKQjuXh0aMzklATuQ==\n" +
                "-----END PKCS #7 SIGNED DATA-----";

            var validationResult =
                _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo, CertCli.CR_IN_PKCS7);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Deny_commonName_invalid_dnsName_invalid_CMC_encoded()
        {
            // CN=this-is-a-test
            // dnsName=this-is-a-test
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIGOQYJKoZIhvcNAQcCoIIGKjCCBiYCAQMxCzAJBgUrDgMCGgUAMIIEkwYIKwYB\n" +
                "BQUHDAKgggSFBIIEgTCCBH0wZDBiAgECBgorBgEEAYI3CgoBMVEwTwIBADADAgEB\n" +
                "MUUwQwYJKwYBBAGCNxUUMTYwNAIBBQwaQ0xJRU5UMi5pbnRyYS5hZGNzbGFib3Iu\n" +
                "ZGUMCklOVFJBXHJ1ZGkMB01NQy5FWEUwggQPoIIECwIBATCCBAQwggLsAgEAMBkx\n" +
                "FzAVBgNVBAMMDnRoaXMtaXMtYS10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                "MIIBCgKCAQEA6hJzcbbvMbAnlwkTKtXWy8CfSGAuQraUFpPrFRUVBWjkKHUAIz+Q\n" +
                "T0TLNLQ82civl3ajzy0KaCCKNXNL3h7I4mfRFl4Vz7Yx+cA/GrUfUXRXbwDZV4wA\n" +
                "mkuBMoXep3rFXzrBgv2DMv7P55FKwAYuyQ5wIGrkWyquU+VnDxhHTUDQXm9dQ4cG\n" +
                "ERjlbOkM9kgEjde8s1Ws3YvMtwOGm1bnFTLo80jhaIDiBrvahj3oJoya0bupLJVT\n" +
                "L4fypkk8H0ztT3/5O/n8CqxmavDVNzMmVl9SMnQlUtct2gJzx9+vnXc+eGRrp2hC\n" +
                "0lfznnVfwNDv7+xTxYLUz9rIFRXZDPcasQIDAQABoIIBpDAcBgorBgEEAYI3DQID\n" +
                "MQ4WDDEwLjAuMTgzNjMuMjBDBgkrBgEEAYI3FRQxNjA0AgEFDBpDTElFTlQyLmlu\n" +
                "dHJhLmFkY3NsYWJvci5kZQwKSU5UUkFccnVkaQwHTU1DLkVYRTByBgorBgEEAYI3\n" +
                "DQICMWQwYgIBAR5aAE0AaQBjAHIAbwBzAG8AZgB0ACAAUgBTAEEAIABTAEMAaABh\n" +
                "AG4AbgBlAGwAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBp\n" +
                "AGQAZQByAwEAMIHKBgkqhkiG9w0BCQ4xgbwwgbkwOwYJKwYBBAGCNxUHBC4wLAYk\n" +
                "KwYBBAGCNxUIg4DSJ4GzrS+ZlxrppUGs9FSBZ4b521KEm4hwAgFkAgEQMBMGA1Ud\n" +
                "JQQMMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIFoDAbBgkrBgEEAYI3FQoEDjAM\n" +
                "MAoGCCsGAQUFBwMBMBkGA1UdEQQSMBCCDnRoaXMtaXMtYS10ZXN0MB0GA1UdDgQW\n" +
                "BBQglePw4hbDLawtDYHqDTdx9rMwAjANBgkqhkiG9w0BAQUFAAOCAQEAtNAv5hgi\n" +
                "zE9Db9u6Wfp4I3l9MC1cwr/IDwvqt72MQ17487DgPLwx8UVTVB2SJDKPOEE8y4BT\n" +
                "T7o/FN8R+lE6SxpGtOufp+r8GKSiUpLJCcdHIqnrPgHO8GBo0u7arCKPyGY7tJ3e\n" +
                "xAAcJlji2mGf/cZe30gRNH4vBvBpuhxzccFWyEAigpF1WhvO1V9nvaZEeZlDPWAJ\n" +
                "NPZvtXsFGQeikrmRnR3uFJ/jtgWBdC9k8Q9huuNv8Bvccj8qYWL/Mtq7DvJQTXSS\n" +
                "2ZnYd5daMmaMwR4PTSMJBL39dcOO13E8V96zNVzk0vyuGV6aj6PYbYG1mcBYhRYo\n" +
                "yGjpsGJCDObrsDAAMAAxggF7MIIBdwIBA4AUIJXj8OIWwy2sLQ2B6g03cfazMAIw\n" +
                "CQYFKw4DAhoFAKA+MBcGCSqGSIb3DQEJAzEKBggrBgEFBQcMAjAjBgkqhkiG9w0B\n" +
                "CQQxFgQUxhKbjHHGqjcaR+dFE/O6k3U0uiMwDQYJKoZIhvcNAQEBBQAEggEA1IqJ\n" +
                "eY7zq0pTPOw2Ejja946kFRgKeRGyFz6tefs8WZs+FVStA0y31o7Lirnz5ipb51hv\n" +
                "vD+J4vWPJzamqlf+XuL3LcqGE2yzmiqPClhdSOnS1YxOup26688NCLPbEXfjYWYL\n" +
                "IKI6SlYKfyl94LSGnZHzK4S7tVxcZ1neXh6b9VgOO4UfyXPWrsPNBfKPJffXkBVb\n" +
                "vTRD/rXcqWn+SM4iTNGbcIMVZdIfMsug1N4twwUrullFrzBcY46FZB2Ht5jFmxHf\n" +
                "b+xocnI5ehrg/rjE9FaCSc63/6vUmwZTg/AhnvYpgWUKjXbfMHa/HtnJnTFRU/Ts\n" +
                "Q2DN9dMpV1FjWqNXdA==\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult =
                _requestValidator.VerifyRequest(request, _requestPolicy, _templateInfo, CertCli.CR_IN_CMC);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Allow_notAfter_valid()
        {
            var requestPolicy = _requestPolicy;
            var notAfter = "2100-12-31T23:59:59.0000000+01:00";
            requestPolicy.NotAfter = notAfter;

            var validationResult = _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.ERROR_SUCCESS));
            Assert.IsTrue(validationResult.NotAfter.Equals(DateTimeOffset.ParseExact(notAfter, "o",
                CultureInfo.InvariantCulture.DateTimeFormat,
                DateTimeStyles.AssumeUniversal)));
        }

        [TestMethod]
        public void Deny_notAfter_invalid()
        {
            var requestPolicy = _requestPolicy;
            requestPolicy.NotAfter = "ThisIsNotAValidDateTime";

            var validationResult = _requestValidator.VerifyRequest(_standardCsr, requestPolicy, _templateInfo);
            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode.Equals(WinError.ERROR_INVALID_TIME));
        }
    }
}