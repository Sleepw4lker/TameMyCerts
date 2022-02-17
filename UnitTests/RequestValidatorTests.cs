using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts;

namespace UnitTests
{
    [TestClass]
    public class RequestValidatorTests
    {
        private readonly CertificateRequestPolicy _requestPolicyRsa, _requestPolicyEcc;
        private readonly CertificateRequestValidator _requestValidator = new CertificateRequestValidator();

        public RequestValidatorTests()
        {
            _requestPolicyRsa = GetSamplePolicy();

            _requestPolicyEcc = GetSamplePolicy();
            _requestPolicyEcc.KeyAlgorithm = "ECC";
            _requestPolicyEcc.MinimumKeyLength = 256;
        }

        private static CertificateRequestPolicy GetSamplePolicy()
        {
            // This function can be used to write a sample XML based policy configuration file
            // This is not in active use by the policy module at the moment

            var policy = new CertificateRequestPolicy
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

        [TestMethod]
        public void Test_NoValidCertificateRequest()
        {
            // Not a CSR at all
            // Should fail, obviously
            const string request = "This is not a certificate request";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_noSan1()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            const string request =
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsTrue(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_noSan2()
        {
            // 3072 Bit RSA Key
            // CN=intranet.adcslabor.de
            // Should succeed
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIEbTCCAtUCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyjjwCxrPjNKv+AWBdX+GoqFf\n" +
                "XZKnFWAoC3Uoz+XV+1KNT6Z+fonnveArgkWko0UcpCSMOYgxnbS0zv75FBbmNNRl\n" +
                "SOkAssM8GYyBmGb3KTdo+1yujEGdyFBYimLMMchJdShpbT8bYcHXPxhq8yFXejwA\n" +
                "Yw6VJ7yUIzWGhu09MrlZOh+jmrUlu55ixOE7ALopmMPEL0J2K2uVHzQKG6ZAG4sA\n" +
                "jEI2mtVkq74YcOtw+iFG1NarDYUyYX1EyfAS2poHpTzs5u2g3qU5B74t5G1t+lMD\n" +
                "Ne0kwlwwbliNYTym+OM2kA01T5vdUzm/F+QtrLEOJr8rhn/od4BobyKfdJhfTUTa\n" +
                "Q7y4f4mm3tl55MH05y9G9oveaQc+M5Xfr9KJ5LzoRxQcXclXmflR9hFssyp48eTU\n" +
                "7O8vooVnBPv1R+1s8TQHZfdN6pwzrKwGRj6sI0kYGGXjEQ4fM3LCh59la8pbBxq5\n" +
                "6pWe6Zx6RdKyAfbtokALNC8YCp2AKGveVKNqccUNAgMBAAGgggEGMBwGCisGAQQB\n" +
                "gjcNAgMxDhYMMTAuMC4xOTA0NC4yMD4GCSqGSIb3DQEJDjExMC8wDgYDVR0PAQH/\n" +
                "BAQDAgeAMB0GA1UdDgQWBBTkic2w2XwII9Wh0o1dqhTOF0khtDA+BgkrBgEEAYI3\n" +
                "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
                "bC5leGUwZgYKKwYBBAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAg\n" +
                "AFMAbwBmAHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBv\n" +
                "AHYAaQBkAGUAcgMBADANBgkqhkiG9w0BAQsFAAOCAYEAekIglX89K4JuUZjcDwWS\n" +
                "swupj8dr2wwYjSmI966k/gysHaRXa9V2a79DIaIl4lUpRlSa0V8rRxZrSMv2fOiQ\n" +
                "2syVpvz+P9Um/bF0GwKCUF9OPDQZdFeJFB7hKjjgv1+cBJUeLTusHrWiURa8IszS\n" +
                "FBGcpR16atHZAGaWZ18XL1lg7HLcb1BPrSNxGKmydL9Ui1hFoJOGT0bBX7n0qdAf\n" +
                "8/ucBtxd7/c8AnrqhQRry6UwBZNQgDRTpbgP0y8G7oBBdydjVk1hAtR5rdhU8AtF\n" +
                "4YLhJglfkHtYg2fsLgIMvbF4YlJ/4ELZdyA2k9dhV0wpA2chkwsqueaAHlSquzGq\n" +
                "JpbpruWH87YfU/xGuLIfoaPvGtTeeOI7fBaF0ag2+70bQ2mZQPW7N8RqS4vVxodW\n" +
                "4Xul3YL7AhyO3luZtW7Oo7I4BCmGx9AZLVXZHADRdtKpqKLtEa/7C3iFGKHJVph8\n" +
                "BzNqID8+ns2bwu/BrEOP04BSBt2yBfVB2l1KhyeXYU0Y\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsTrue(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_noSan3()
        {
            // 4096 Bit RSA Key
            // CN=intranet.adcslabor.de
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIFbTCCA1UCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIC\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtU8a8CjIlwCgC0mFnpB586id\n" +
                "fC86ZbFSr6vTUnPQ7Cw45QgzatWbvFh5XvSz1BwlrGtvRYId12uAIENRTfkm6EnR\n" +
                "uuTGGi58yFLBHjbSnTv43+gkoO0zqNP70GS8V6mOp5nuCBfl+Y1Mz/s29J/ajWOv\n" +
                "P3/udF/DfBCQhZbwOoDxMvvxZhjrGUxWWGnp7U2cYqJqeifR19aPjP1bvtMzXKo7\n" +
                "I8+xoZM4OkQBhrEiOLKm6mfnwP+aQ3eOXI1RCrnGhSjROygfgyHtgIuto+u41sC1\n" +
                "zGuSIPhuIYFswyBz3hKBtmffWAlBKJQSfSdsX5YqZ5j9sfmCE+KWNdQb7Blb3wZI\n" +
                "KGXFUfSECUWPMFAmfRtAoKW+17+SSkZ63IrXV6EXhwFJkhk0NLnf1VsbuGNhaYEa\n" +
                "LTck35R+WsgaT0U5BydvNXb/dpvSUBGCq8Zl6pF8iahOjulSsE9PTr/gLwRhkbxb\n" +
                "hLbsCvTjFbE9gZsqKjgnoRq05DZVLphk2IG6my/I5LjzWRhXk+ql30dsCLEcEau9\n" +
                "zy0Swofc/P/VxEr3usFIWjAcOCfwZUD6zNgJ3dVYYAa8wKPeCXC9UZE1gKN0DeU+\n" +
                "dFNhy7YpSMVxTURIzyn6gRi7CuqaVHOzVdIkJPdQscMz18V1oMtG9ynUH7K+uF5C\n" +
                "+AfqKNYVs/TV0It2tqkCAwEAAaCCAQYwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE5\n" +
                "MDQ0LjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYE\n" +
                "FAWN/Qh1jqs+vE8hTPh5QPoKYT5eMD4GCSsGAQQBgjcVFDExMC8CAQUMCm90dGkt\n" +
                "b3R0ZWwMDk9UVEktT1RURUxcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3\n" +
                "DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBl\n" +
                "ACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMA0G\n" +
                "CSqGSIb3DQEBCwUAA4ICAQAGjaejM70SeUvfniOaNnvpYC1FdtXfkYUALzAEb1rE\n" +
                "lThRebLEwhgmO61RGOC6Ku7Ea6BVzukrofsihNhDrjRG3Gm5uoa7UsowdvNwt/Td\n" +
                "wxxTbf2cHoSQ2U3PF++r4Amf1cagLzX2iWbadShiK531ag30ja6UYSqhhehDHRx8\n" +
                "XAhdG+BP4MSuZgyQjznA8LqfzokHwOAFaMwB1RO63qVih2KvSvbuuGXL2f23534S\n" +
                "qIdgevb+j45IFbn0FWegBexioLGYdqLT+Aq8e9FszVX9ceuQ55v01DmfwYt9yN4F\n" +
                "pe6O3YeAgFyZE/o9SYJGBIgo4LKRXzWGYK+caAUv8vyTWQKk0fpLvg54nYc7XGSa\n" +
                "kPW8H0JZjt/iM67ru/n5PzIW+VlIllGDG2YXJfYPuPWJKyHnEepvEBZVwrEETrWM\n" +
                "KdG4iCPjkhOPTj7pMyHIY3CuxlnrsRyoT/QJzL406G6rRTOBZTHSAwezje8tlUsj\n" +
                "vFPiDORVcO5Gujl/kXY0uz4Bn24NYkw1ZAErLEAauNBKiP9o8cNS7lzjRxQa7a+9\n" +
                "Ze3iiIiWjXVLMQ8G+c9evtglZ7IYGQydDbBL59prAAC8aQGw94Yzq6kBTuS9ZBzQ\n" +
                "z3I9jzynPA0Z7BJiNa3uqLfmoMeid92VBGMNHLu+9LDZ4nD/nJAiZYxml4L+f+WA\n" +
                "sw==\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsTrue(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_noSan4()
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsTrue(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_noSan5()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de,C=DE,O=ADCS Labor
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDjzCCAncCAQAwQjETMBEGA1UEChMKQURDUyBMYWJvcjELMAkGA1UEBhMCREUx\n" +
                "HjAcBgNVBAMTFWludHJhbmV0LmFkY3NsYWJvci5kZTCCASIwDQYJKoZIhvcNAQEB\n" +
                "BQADggEPADCCAQoCggEBAL6pMqepA0/cntKtKpHCruBWCKOI0a3WNvNZT5zy6aJv\n" +
                "+J3f3xROZ76DFD1H491wPj6ANpH95A5zgzdixY0K/SgWjO/6836+QOPobeflS3Dg\n" +
                "Bhb2I+6sNNHobhAm0Ojd+/2IlRUpTHT4idhmRkJd07rRX4pirzWhqcnK5Lz0x22k\n" +
                "WgjxtRaCgWO6w2PIEs0pL5NEca3zThWSWeSn0WAnm6VqhM8t8kbKugxuEQl1cquz\n" +
                "d299idbukS6p/c9CEX7N8rwXe0BJ2IjtmvlPeelweHHELDOzIpSs3ek9rOh6vGxH\n" +
                "xwqdbrNsg09YGA5xnXab6bHmiKbMecEF8r+t/GSGm+UCAwEAAaCCAQYwHAYKKwYB\n" +
                "BAGCNw0CAzEOFgwxMC4wLjE5MDQ0LjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8B\n" +
                "Af8EBAMCB4AwHQYDVR0OBBYEFGoY0+GDC+oPAeGFYY6xo7bvOuElMD4GCSsGAQQB\n" +
                "gjcVFDExMC8CAQUMCm90dGktb3R0ZWwMDk9UVEktT1RURUxcdXdlDA5wb3dlcnNo\n" +
                "ZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0\n" +
                "ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUABy\n" +
                "AG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBAQBoUIzg+DClxewILXI4\n" +
                "tbIHrZsa8x/XeCjVfoM/bHFzijt11497fvmOwyue+7N339gnyV7mLT2ojttcHg1H\n" +
                "O1VAdTzHc2nJQHIFH2iG94OsL+BgppQoprQABrVT/0+4zvhAhNrE4y710BO71I5g\n" +
                "Rb6UW1Kcq1kA76y4mLEYELmPc/SG672XtgQ15W09sOHAINZ8DO4GeGa9fbIwa0r4\n" +
                "yA2gPwPgHenmrxS9nJ5Bmk3aQ51A/Nnw70HILkVKt8VV7dKptVJfD8OtLTipkYoP\n" +
                "UXXme3TL8f1RTHggDdA233s6CmdCA8wZCQ8IB85yEFoTSQW/GVPAoJUdDAT0IDxZ\n" +
                "cGFP\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsTrue(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_noSan6()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de,C=DE,O=ADCS Labor,L=Munich
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDoDCCAogCAQAwUzEPMA0GA1UEBxMGTXVuaWNoMRMwEQYDVQQKEwpBRENTIExh\n" +
                "Ym9yMQswCQYDVQQGEwJERTEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRl\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2VevkdgfUvn/+Ticwlr2\n" +
                "WZ1nhjDD+1V7XEwpowCj1qr+UKV///fM7QeKuWM4mcc2W5JZOxmYQtF5k/gc8WRo\n" +
                "YAeSEgXFTNsIPD2LIwLGfDX5aW8oEKlCParskfOpSO4wsRPijzciBx2p3OWHWVhv\n" +
                "HVx7hQHtHG/cQheHcC9q15YowbQRfM3j6G8JmTpWgt1+58QyrC6gNu5sN/0V0pXp\n" +
                "0e4ReH/GvztI8qodlcmazgv9CtEHTZ/uB9qmuKCPkUuOvbwpZdyEtUbqM5AG/d2e\n" +
                "lx6glD5bVskhhGW2d7E3BFprjOPK0tCqghtrdXjKfTK6dzbwRWpgLx56omtiql3P\n" +
                "KQIDAQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkqhkiG\n" +
                "9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUijBNQp/tH0/5ovHJ\n" +
                "dgPQxCSY7vEwPgYJKwYBBAGCNxUUMTEwLwIBBQwKb3R0aS1vdHRlbAwOT1RUSS1P\n" +
                "VFRFTFx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcNAgIxWDBWAgEAHk4A\n" +
                "TQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMA\n" +
                "dABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJKoZIhvcNAQELBQAD\n" +
                "ggEBADXsUG4WDt32kEi+9vSuw3jbTjC7uAtNvCrMJ9b/WBrbyJXUPjKSOJJaNDuA\n" +
                "AImqC4TPq3aHspxv4qlQWxjuHdphpvqZY7fVhQo/1P1ulK2NfzxTwix1Ec47ipfB\n" +
                "cVTDHYBdyW0IXSPT5w2eXn7lfaj2PuuiBkFsXbZpArKZjlD7shtxUCC88nhqVGnz\n" +
                "ZYF+PGD7jK2a5rX1ZTRPVEz+MCSEgPjVbZPbPxA+qLq6RXJsYOegeevZvU5w7kVc\n" +
                "uE0phJLr1VumyThHe+kZYmBf7yLoHmAwajtLWNzB0ueK97x5ANQI317p592oa/4L\n" +
                "gvfJNz3+Ekwld3em310aFCyRyg4=\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsTrue(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_WrongKeyAlgorithm()
        {
            // ECDSA_P256 Key
            // CN=intranet.adcslabor.de
            // Should fail because no ECC keys allowed
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_KeyTooSmall()
        {
            // 1024 Bit Key
            // CN=intranet.adcslabor.de
            // Should fail because key is too small
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_KeyTooLarge()
        {
            // 8192 Bit Key
            // CN=intranet.adcslabor.de
            // Should fail because key is too large
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }



        [TestMethod]
        public void Test_ECC_ValidCommonName_noSan1()
        {
            // ECDSA_P256 Key
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyEcc);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsTrue(validationResult.Success);
        }

        [TestMethod]
        public void Test_ECC_ValidCommonName_noSan2()
        {
            // ECDH_P256 Key
            // CN=intranet.adcslabor.de
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIB5TCCAYoCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMFkw\n" +
                "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi0s5enmvjkR6gp2adIp4W+LUI+x6ufri\n" +
                "5kOYCsqNFTvL8FFX7Zy3cAcHJpwZXS0k5B2rKZbOdU4NYHmiRy4K6aCCAQYwHAYK\n" +
                "KwYBBAGCNw0CAzEOFgwxMC4wLjE5MDQ0LjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNV\n" +
                "HQ8BAf8EBAMCB4AwHQYDVR0OBBYEFOJSrTWtY+PpP+iWLiLBR0ozTLOAMD4GCSsG\n" +
                "AQQBgjcVFDExMC8CAQUMCm90dGktb3R0ZWwMDk9UVEktT1RURUxcdXdlDA5wb3dl\n" +
                "cnNoZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
                "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
                "UAByAG8AdgBpAGQAZQByAwEAMAoGCCqGSM49BAMCA0kAMEYCIQCsYBFqP/0g6X/k\n" +
                "yQsaCIF+tRcJslFxhRA+UQLtLnOJ+wIhANAYdg8WMwkkDFUkgyFzCEZp94SlbIFk\n" +
                "wlGn5D3y0MUy\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyEcc);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsTrue(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_ValidSan1()
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsTrue(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_ValidSan2()
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsTrue(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_ValidSan3()
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsTrue(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_InvalidSan1()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // dnsName=intra.adcslabor.de (blacklisted)
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIDjzCCAncCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0hBodHHRjazold4WUUjxy3lk\n" +
                "S3E7p74NhcY3xmE3x+Wu4J35cCcMKr5z+axt0qQnrE8mIYLfIudWcECXp5sqUVaG\n" +
                "PdjSt1kpeCgGZ8GBS0sUEDc7gYAFUiz1eh78wX/S1O5zunnY4LKW7ngulVtP7+qQ\n" +
                "M9QLWtlvEP9757Wz3N9JD+seTWN0nioHNiqzGq1Ho7EMDb139q1tYZvR/9R2CL7/\n" +
                "pZemqMYHhYJ7RsuWs4+qG6vOiOOnBPGfs2ARGf0Kpoe9Sl417m4vtb+b3KpvL3LZ\n" +
                "SwGIx0BCL/v2xGS6OzWJTaixsaxvlL771M30JgCS5pALLnifMApC1hHGcy9f9QID\n" +
                "AQABoIIBKDAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
                "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
                "bC5leGUwYAYJKoZIhvcNAQkOMVMwUTAOBgNVHQ8BAf8EBAMCB4AwIAYDVR0RAQH/\n" +
                "BBYwFIISaW50cmEuYWRjc2xhYm9yLmRlMB0GA1UdDgQWBBRaBoJLQwVf0P+3HoAV\n" +
                "9HENShVSgjBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0\n" +
                "ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUABy\n" +
                "AG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBAQDKPP68j+z/9LJGwMHr\n" +
                "MUoleLu47NJ4Aiz6ocBPoKXkaOKorUmmzzMw9uqlP61IfnaTCyTbdwCEWbNQ21qS\n" +
                "5O4n8fsX7OpL5WkyjetaBCT4lD+89avt7nB1VtKGqjVPfATPX2udNkWoqXwRPuj7\n" +
                "PO4kcChBnA6VrsVPDaHfoWjyzuz2ZIJziMgUHXPD8c9hYtIzsQ9iv+em2fAKq9K0\n" +
                "byTXZhNd64JwrGdMyfQAZn2sAdELJLou7KGcRGbFM0EWahIn9oDnqgBTQwu7sg1C\n" +
                "qkQYNKTPAA9CSlUiqdcRDbT7YGLWpGd2JqzPyCyl5rjg0QKmHcV1CLKrrO7ioiXT\n" +
                "jmBG\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_InvalidSan2()
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_InvalidSan3()
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_ValidCommonName_InvalidSan4()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            // dnsName=web1.adcslabor.de,web2.adcslabor.de,web3.adcslabor.de,web4.adcslabor.de,web5.adcslabor.de,web6.adcslabor.de,web7.adcslabor.de,web8.adcslabor.de,web9.adcslabor.de,web10.adcslabor.de,web11.adcslabor.de
            // Should fail because of too many dnsNames specified
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_InvalidCommonName_noSan1()
        {
            // CN=
            // Should fail because CN doesnt match policy
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_InvalidCommonName_noSan2()
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_InvalidCommonName_noSan3()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de,C=UK,O=ADCS Labor,L=Munich
            // Should fail because of invalid countryName
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }

        [TestMethod]
        public void Test_RSA_InvalidCommonName_noSan4()
        {
            // 2048 Bit RSA Key
            // "CN=intranet.adcslabor.de,G=Test"
            // Should fail because givenName is not defined in policy
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

            var validationResult = _requestValidator.VerifyRequest(request, _requestPolicyRsa);
            Console.WriteLine(string.Join("\n", validationResult.Description));

            Assert.IsFalse(validationResult.Success);
        }
    }
}