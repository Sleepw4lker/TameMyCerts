using System;
using System.Collections.Generic;
using System.ComponentModel;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;

namespace TameMyCerts.Tests
{
    [TestClass]
    public class FinalResultValidatorTests
    {
        private readonly CertificateRequestPolicy _policy;
        private readonly string _request;
        private readonly FinalResultValidator _validator = new FinalResultValidator();

        public FinalResultValidatorTests()
        {
            // 2048 Bit RSA Key
            // CN=,C=DE
            _request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIEcTCCAtkCAQAwGDELMAkGA1UEBhMCREUxCTAHBgNVBAMTADCCAaIwDQYJKoZI\n" +
                "hvcNAQEBBQADggGPADCCAYoCggGBAMID8rc/c2v1bGVuzi2480adyXuT9ps8zWe2\n" +
                "dxUIt1BC6Qrp+Qog/dy9wJhuzz6e4QRKseWg8fubMKIWtKjvlOsG+OzG0cDhDsP9\n" +
                "r0Kvd2YCXw2kqWFBe1Y885bNX1B13R/vK3/LO4CNOUlAKrlvJPbGStQIQF8dZ2wB\n" +
                "IYhamPK5hic1zOk2PTw9QLLl9Bfmh53A6Beguj+C3WdQl1TDO24kg68D4ZhDiNE6\n" +
                "votstfNZWYZ/MvOUeHB1f2TNz1QxEvPTpOif2DXxLEvW7yrLd/dGUq+owh91qI04\n" +
                "Sv5IP3XVCFm4yRPy5Dn7U0DSv2QNOxbLX5vUwpKLcE38MKvgK4MPxG1TU2gtEwqA\n" +
                "p8YrJUNPGoKx8rsv7tI41Xa9uPZAmdm3UpsssxSh3ZwBQs2NY0DobFODPT4QPBL+\n" +
                "Kdg122GlOMSnPahpfqLy10vnKKRr0U5E8raMOB6aGpAzlNTQe53ZlW2EanolzMOB\n" +
                "ZVgFhyGvWJd1axinuaBAAVs1lMlGSQIDAQABoIIBEjAcBgorBgEEAYI3DQIDMQ4W\n" +
                "DDEwLjAuMTgzNjMuMjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAd\n" +
                "BgNVHQ4EFgQUWIHnwcy8A89ImgQIKvPQbTCIXwswSgYJKwYBBAGCNxUUMT0wOwIB\n" +
                "BQwaQ0xJRU5UMi5pbnRyYS5hZGNzbGFib3IuZGUMCklOVFJBXHJ1ZGkMDnBvd2Vy\n" +
                "c2hlbGwuZXhlMGYGCisGAQQBgjcNAgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBm\n" +
                "AHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQ\n" +
                "AHIAbwB2AGkAZABlAHIDAQAwDQYJKoZIhvcNAQELBQADggGBAA8H7M16sY8/8feg\n" +
                "IU2GEmb+FzZlxkUp12kCS5j89JBgvEseU8vCnBChMjji2/wq3Ibc6SXaRFFs+SdR\n" +
                "hbde9MlzdnDp8mOToRkYj95WFNPxpZqi4QqUgpJy3s7bewLzXz3r4JS01qWEzE4a\n" +
                "8Aeqxd38Gwp2SSd2SVtp8SwpdfswEZke5Y9Cy1GiA4yK4rEZ4i5nhq3BuyQLhcOh\n" +
                "0iJod1Q4grQ9cTePETOMi9Llv+SI3iIOLtu6qQaWLerEQf1aGE4e5HQlgFckrFz9\n" +
                "yuIWtmfOnU4S53mkkwLG89E0Bu5r0wb+Q4Ytv3fm1LTYxc+Ezdb3hqklFfFmFumY\n" +
                "QFkXmP2HoXo7Exrm2LzkJrGbh9Aa+Ic9O9B5j7OAjRBNmGSM05guU7ssgqGu2OcC\n" +
                "JDMTSVRtnIF2SNJ3MflnTzv8fwPFQEkCPIikgKy4HEG7KkmelOOR9DVrgot0WXHD\n" +
                "xkuECyANnFYngtst+/c9pxSkHICCzmFYqrg9RK6GI57INCr2nQ==\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            _policy = new CertificateRequestPolicy
            {
                ReadSubjectFromRequest = true,
                Subject = new List<SubjectRule>
                {
                    new SubjectRule
                    {
                        Field = RdnTypes.CommonName,
                        Patterns = new List<Pattern>
                        {
                            new Pattern { Expression = @"^.*$" }
                        }
                    },
                    new SubjectRule
                    {
                        Field = RdnTypes.Country,
                        Patterns = new List<Pattern>
                        {
                            // ISO 3166 country codes as example... to ensure countryName is filled correctly (e.g. "GB" instead of "UK")
                            new Pattern
                            {
                                Expression = @"^(DE)$"
                            }
                        }
                    }
                },
                SubjectAlternativeName = new List<SubjectRule>
                {
                    new SubjectRule
                    {
                        Field = SanTypes.DnsName,
                        Patterns = new List<Pattern>
                        {
                            new Pattern { Expression = @"^.*$" }
                        }
                    }
                }
            };
        }

        internal void PrintResult(CertificateRequestValidationResult result)
        {
            Console.WriteLine("0x{0:X} ({0}) {1}.", result.StatusCode,
                new Win32Exception(result.StatusCode).Message);
            Console.WriteLine(string.Join("\n", result.Description));
        }


        [TestMethod]
        public void Does_return_if_already_denied()
        {
            var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

            var result = new CertificateRequestValidationResult(dbRow);
            result.SetFailureStatus();

            result = _validator.VerifyRequest(result, _policy, dbRow);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.NTE_FAIL));
        }

        [TestMethod]
        public void Does_deny_if_no_identity_is_present()
        {
            var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

            var result = new CertificateRequestValidationResult(dbRow);
            result = _validator.VerifyRequest(result, _policy, dbRow);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Does_deny_if_empty_identity_is_set()
        {
            var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

            var result = new CertificateRequestValidationResult(dbRow);

            result.SetSubjectDistinguishedName(RdnTypes.CommonName, string.Empty);
            result = _validator.VerifyRequest(result, _policy, dbRow);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Does_deny_if_no_identity_is_present_inline()
        {
            var policy = _policy;
            policy.ReadSubjectFromRequest = true;

            var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

            var result = new CertificateRequestValidationResult(dbRow);
            result = _validator.VerifyRequest(result, policy, dbRow);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        }

        [TestMethod]
        public void Does_not_deny_if_no_identity_is_present_and_allowed()
        {
            var policy = _policy;
            policy.PermitEmptyIdentities = true;

            var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

            var result = new CertificateRequestValidationResult(dbRow);
            result = _validator.VerifyRequest(result, policy, dbRow);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Does_not_deny_if_commonName_is_present()
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

            var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

            var result = new CertificateRequestValidationResult(dbRow);

            result = _validator.VerifyRequest(result, _policy, dbRow);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Does_not_deny_if_commonName_is_present_inline()
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

            var policy = _policy;
            policy.ReadSubjectFromRequest = true;

            var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

            var result = new CertificateRequestValidationResult(dbRow);
            result = _validator.VerifyRequest(result, policy, dbRow);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Does_not_deny_if_dNSName_is_present()
        {
            // NISTP256 key
            // dNSName=this-is-a-test
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIB4jCCAYgCAQAwADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNZt9QPDs5V3\n" +
                "l+BQe4j6P+TEVU/eA2rpf9QMYXXZt+puoc1+p5YprXg7qx0vam+zR+6ebrdZcX+z\n" +
                "t+nuzzzye46gggEkMBwGCisGAQQBgjcNAgMxDhYMMTAuMC4yMjYyMS4yMD4GCSsG\n" +
                "AQQBgjcVFDExMC8CAQUMCkxBUFRPUC1VV0UMDkxBUFRPUC1VV0VcdXdlDA5wb3dl\n" +
                "cnNoZWxsLmV4ZTBcBgkqhkiG9w0BCQ4xTzBNMA4GA1UdDwEB/wQEAwIHgDAcBgNV\n" +
                "HREBAf8EEjAQgg50aGlzLWlzLWEtdGVzdDAdBgNVHQ4EFgQU2tBcD6jV0gqT+EKX\n" +
                "8CtxBZVkKkAwZgYKKwYBBAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYA\n" +
                "dAAgAFMAbwBmAHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAA\n" +
                "cgBvAHYAaQBkAGUAcgMBADAKBggqhkjOPQQDAgNIADBFAiEAn0SZlLB2wdnkDdHg\n" +
                "CLptVjWCRiz7H+7jVD2cQT7YuRcCIHg/jY7EFBW3k8waSeYhF5hV1YD4LdsIuXxJ\n" +
                "SvrFrlKk\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

            var result = new CertificateRequestValidationResult(dbRow);
            result = _validator.VerifyRequest(result, _policy, dbRow);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Does_not_deny_if_iPAddress_is_present()
        {
            // NISTP256 key
            // iPAddress=192.168.0.1
            const string request =
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
                "MIIB2TCCAX4CAQAwADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC++b7RlkCgZ\n" +
                "rl/pgYzFhRFypGo5nqVUkuHYTm9UIpB9GNFoaG02Pfl1+Bk6AA3GpSogtIZBQ/YU\n" +
                "7/c8U8TxSSagggEaMBwGCisGAQQBgjcNAgMxDhYMMTAuMC4yMjYyMS4yMD4GCSsG\n" +
                "AQQBgjcVFDExMC8CAQUMCkxBUFRPUC1VV0UMDkxBUFRPUC1VV0VcdXdlDA5wb3dl\n" +
                "cnNoZWxsLmV4ZTBSBgkqhkiG9w0BCQ4xRTBDMA4GA1UdDwEB/wQEAwIHgDASBgNV\n" +
                "HREBAf8ECDAGhwTAqAABMB0GA1UdDgQWBBTZGG7deEosuhoxmvI8dt3MvTfxATBm\n" +
                "BgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYA\n" +
                "dAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQA\n" +
                "ZQByAwEAMAoGCCqGSM49BAMCA0kAMEYCIQCUAUsHYuqm+sCYjvTC/jGg15UxDF4O\n" +
                "ig829nNLX7EGkAIhAOxqerUSBdJETwd0oRKKF1k9bzU4C7miJagnBfZatkYv\n" +
                "-----END NEW CERTIFICATE REQUEST-----";

            var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

            var result = new CertificateRequestValidationResult(dbRow);
            result = _validator.VerifyRequest(result, _policy, dbRow);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
        }
    }
}