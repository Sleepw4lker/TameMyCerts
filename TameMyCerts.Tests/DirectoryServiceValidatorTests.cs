using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Principal;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;

namespace TameMyCerts.Tests
{
    [TestClass]
    public class DirectoryServiceValidatorTests
    {
        private readonly CertificateDatabaseRow _dbRow;
        private readonly ActiveDirectoryObject _dsObject;
        private readonly ActiveDirectoryObject _dsObject2;
        private readonly CertificateRequestPolicy _policy;
        private readonly DirectoryServiceValidator _validator = new DirectoryServiceValidator(true);

        public DirectoryServiceValidatorTests()
        {
            // 2048 Bit RSA Key
            // CN=intranet.adcslabor.de
            var request =
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

            _dsObject = new ActiveDirectoryObject(
                "CN=rudi,OU=Test-Users,DC=intra,DC=adcslabor,DC=de",
                0,
                new List<string> { "CN=PKI_UserCert,OU=ADCSLabor Gruppen,DC=intra,DC=adcslabor,DC=de" },
                new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase)
                {
                    { "c", "DE" },
                    { "company", "ADCS Labor" },
                    { "displayName", "Rudi Ratlos" },
                    { "department", "IT Operations" },
                    { "givenName", "Rudi" },
                    { "initials", "RR" },
                    { "l", "München" },
                    { "mail", "rudi@adcslabor.de" },
                    { "name", "rudi" },
                    { "sAMAccountName", "rudi" },
                    { "sn", "Ratlos" },
                    { "st", "Bavaria" },
                    // Note that streetAddress is left out intentionally
                    { "title", "General Manager" },
                    { "userPrincipalName", "rudi@intra.adcslabor.de" },
                    { "extensionAttribute1", "rudi1@intra.adcslabor.de" },
                    { "extensionAttribute2", "rudi2@intra.adcslabor.de" }
                },
                new SecurityIdentifier("S-1-5-21-1381186052-4247692386-135928078-1225"),
                new List<string>()
            );

            _dsObject2 = new ActiveDirectoryObject(
                "CN=rudi,OU=Test-Users,DC=intra,DC=adcslabor,DC=de",
                UserAccountControl.ACCOUNTDISABLE,
                new List<string> { "CN=PKI_UserCert,OU=ADCSLabor Gruppen,DC=intra,DC=adcslabor,DC=de" },
                new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase)
                {
                    { "c", "DE" },
                    { "company", "ADCS Labor" },
                    { "displayName", "Rudi Ratlos" },
                    { "department", "IT Operations" },
                    { "givenName", "Rudi" },
                    { "initials", "RR" },
                    { "l", "München" },
                    { "mail", "rudi@adcslabor.de" },
                    { "name", "rudi" },
                    { "sAMAccountName", "rudi" },
                    { "sn", "Ratlos" },
                    { "st", "Bavaria" },
                    // Note that streetAddress is left out intentionally
                    { "title", "General Manager" },
                    { "userPrincipalName", "rudi@intra.adcslabor.de" },
                    { "extensionAttribute1", "rudi1@intra.adcslabor.de" },
                    { "extensionAttribute2", "rudi2@intra.adcslabor.de" }
                },
                new SecurityIdentifier("S-1-5-21-1381186052-4247692386-135928078-1225"),
                new List<string>()
            );

            _policy = new CertificateRequestPolicy
            {
                DirectoryServicesMapping = new DirectoryServicesMapping
                {
                    AllowedSecurityGroups = new List<string>
                        { "CN=PKI_UserCert,OU=ADCSLabor Gruppen,DC=intra,DC=adcslabor,DC=de" }
                },
                SecurityIdentifierExtension = "Add"
            };

            _dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);
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
            var result = new CertificateRequestValidationResult(_dbRow);
            result.SetFailureStatus();
            result = _validator.VerifyRequest(result, _policy, _dsObject2);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.NTE_FAIL));
        }

        [TestMethod]
        public void Allow_disabled_account_if_configured()
        {
            var policy = _policy;
            policy.DirectoryServicesMapping.PermitDisabledAccounts = true;

            var result = new CertificateRequestValidationResult(_dbRow);
            result = _validator.VerifyRequest(result, policy, _dsObject2);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Deny_disabled_account()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            result = _validator.VerifyRequest(result, _policy, _dsObject2);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Allow_if_member_of_allowed_group()
        {
            var result = new CertificateRequestValidationResult(_dbRow);

            result = _validator.VerifyRequest(result, _policy, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Deny_if_not_member_of_any_allowed_group()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            var dsObject = _dsObject;

            dsObject.MemberOf.Clear();

            result = _validator.VerifyRequest(result, _policy, dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_if_member_of_forbidden_group()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);
            var dsObject = _dsObject;

            dsObject.MemberOf.Add("test");
            policy.DirectoryServicesMapping.DisallowedSecurityGroups.Add("test");

            result = _validator.VerifyRequest(result, policy, dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Allow_and_add_SID_extension_if_configured()
        {
            const string expectedSecurityIdentifier =
                "MD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMzgxMTg2MDUyLTQyNDc2OTIzODYtMTM1OTI4MDc4LTEyMjU=";

            var result = new CertificateRequestValidationResult(_dbRow);
            result = _validator.VerifyRequest(result, _policy, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
            Assert.IsTrue(result.CertificateExtensions.ContainsKey(WinCrypt.szOID_DS_CA_SECURITY_EXT) &&
                          Convert.ToBase64String(
                                  result.CertificateExtensions[WinCrypt.szOID_DS_CA_SECURITY_EXT])
                              .Equals(expectedSecurityIdentifier));
        }

        [TestMethod]
        public void Allow_and_add_SID_Uri_if_configured()
        {
            const string expectedSan =
                "MFCGTnRhZzptaWNyb3NvZnQuY29tLDIwMjItMDktMTQ6c2lkOlMtMS01LTIxLTEzODExODYwNTItNDI0NzY5MjM4Ni0xMzU5MjgwNzgtMTIyNQ==";

            var policy = _policy;
            policy.DirectoryServicesMapping.AddSidUniformResourceIdentifier = true;

            var result = new CertificateRequestValidationResult(_dbRow);
            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
            Assert.IsTrue(result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
                          Convert.ToBase64String(
                                  result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                              .Equals(expectedSan));
        }

        [TestMethod]
        public void Allow_but_dont_add_SID_extension_if_allowed()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.SecurityIdentifierExtension = "Allow";

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsFalse(result.CertificateExtensions.ContainsKey(WinCrypt.szOID_DS_CA_SECURITY_EXT));
        }

        [TestMethod]
        public void Allow_but_dont_add_SID_extension_if_denied()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.SecurityIdentifierExtension = "Deny";

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsFalse(result.CertificateExtensions.ContainsKey(WinCrypt.szOID_DS_CA_SECURITY_EXT));
        }

        [TestMethod]
        public void Does_supplement_one_spn()
        {
            const string expectedResult = "MCaCJHRoaXMtaXMtYS10ZXN0LnRhbWVteWNlcnRzLXRlc3RzLmNvbQ==";

            var policy = _policy;
            policy.DirectoryServicesMapping.SupplementServicePrincipalNames = true;

            var result = new CertificateRequestValidationResult(_dbRow);

            var dsObject = _dsObject;
            dsObject.ServicePrincipalNames.Add("HOST/this-is-a-test.tamemycerts-tests.com");

            result = _validator.VerifyRequest(result, policy, dsObject);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
            Assert.IsTrue(
                result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
                Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                    .Equals(expectedResult));
        }

        [TestMethod]
        public void Does_supplement_four_spns()
        {
            const string expectedResult =
                "MIGYgiR0aGlzLWlzLTEtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5jb22CJHRoaXMt" +
                "aXMtMi10ZXN0LnRhbWVteWNlcnRzLXRlc3RzLmNvbYIkdGhpcy1pcy0zLXRlc3Qu" +
                "dGFtZW15Y2VydHMtdGVzdHMuY29tgiR0aGlzLWlzLTQtdGVzdC50YW1lbXljZXJ0" +
                "cy10ZXN0cy5jb20=";

            var policy = _policy;
            policy.DirectoryServicesMapping.SupplementServicePrincipalNames = true;

            var result = new CertificateRequestValidationResult(_dbRow);

            var dsObject = _dsObject;
            dsObject.ServicePrincipalNames.Add("HOST/this-is-1-test.tamemycerts-tests.com");
            dsObject.ServicePrincipalNames.Add("TERMSRV/this-is-2-test.tamemycerts-tests.com");
            dsObject.ServicePrincipalNames.Add("HTTP/this-is-3-test.tamemycerts-tests.com");
            dsObject.ServicePrincipalNames.Add("WSMAN/this-is-4-test.tamemycerts-tests.com");

            result = _validator.VerifyRequest(result, policy, dsObject);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
            Assert.IsTrue(
                result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
                Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                    .Equals(expectedResult));
        }

        [TestMethod]
        public void Does_supplement_unqualified_names()
        {
            const string expectedResult =
                "MCiCGXF1YWxpZmllZC50YW1lbXljZXJ0cy5jb22CC3VucXVhbGlmaWVk";

            var policy = _policy;
            policy.DirectoryServicesMapping.SupplementServicePrincipalNames = true;

            var result = new CertificateRequestValidationResult(_dbRow);

            var dsObject = _dsObject;
            dsObject.ServicePrincipalNames.Add("HOST/qualified.tamemycerts.com");
            dsObject.ServicePrincipalNames.Add("HOST/unqualified");

            result = _validator.VerifyRequest(result, policy, dsObject);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
            Assert.IsTrue(
                result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
                Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                    .Equals(expectedResult));
        }

        [TestMethod]
        public void Does_not_supplement_unqualified_names()
        {
            const string expectedResult =
                "MBuCGXF1YWxpZmllZC50YW1lbXljZXJ0cy5jb20=";

            var policy = _policy;
            policy.DirectoryServicesMapping.SupplementServicePrincipalNames = true;
            policy.SupplementUnqualifiedNames = false;

            var result = new CertificateRequestValidationResult(_dbRow);

            var dsObject = _dsObject;
            dsObject.ServicePrincipalNames.Add("HOST/qualified.tamemycerts.com");
            dsObject.ServicePrincipalNames.Add("HOST/unqualified");

            result = _validator.VerifyRequest(result, policy, dsObject);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
            Assert.IsTrue(
                result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
                Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                    .Equals(expectedResult));
        }

        [TestMethod]
        public void Does_not_supplement_spn_if_already_present()
        {
            const string expectedResult =
                "MIGYgiR0aGlzLWlzLTEtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5jb22CJHRoaXMt" +
                "aXMtMi10ZXN0LnRhbWVteWNlcnRzLXRlc3RzLmNvbYIkdGhpcy1pcy0zLXRlc3Qu" +
                "dGFtZW15Y2VydHMtdGVzdHMuY29tgiR0aGlzLWlzLTQtdGVzdC50YW1lbXljZXJ0" +
                "cy10ZXN0cy5jb20=";

            var policy = _policy;
            policy.DirectoryServicesMapping.SupplementServicePrincipalNames = true;

            var result = new CertificateRequestValidationResult(_dbRow);

            result.SubjectAlternativeNameExtension.AddDnsName("this-is-1-test.tamemycerts-tests.com");

            var dsObject = _dsObject;
            // this one is already present
            dsObject.ServicePrincipalNames.Add("HOST/this-is-1-test.tamemycerts-tests.com");
            dsObject.ServicePrincipalNames.Add("TERMSRV/this-is-2-test.tamemycerts-tests.com");
            dsObject.ServicePrincipalNames.Add("HTTP/this-is-3-test.tamemycerts-tests.com");
            dsObject.ServicePrincipalNames.Add("WSMAN/this-is-4-test.tamemycerts-tests.com");

            result = _validator.VerifyRequest(result, policy, dsObject);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
            Assert.IsTrue(
                result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
                Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                    .Equals(expectedResult));
        }

        [TestMethod]
        public void Does_not_supplement_spn_if_invalid()
        {
            const string expectedResult =
                "MIGYgiR0aGlzLWlzLTEtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5jb22CJHRoaXMt" +
                "aXMtMi10ZXN0LnRhbWVteWNlcnRzLXRlc3RzLmNvbYIkdGhpcy1pcy0zLXRlc3Qu" +
                "dGFtZW15Y2VydHMtdGVzdHMuY29tgiR0aGlzLWlzLTQtdGVzdC50YW1lbXljZXJ0" +
                "cy10ZXN0cy5jb20=";

            var policy = _policy;
            policy.DirectoryServicesMapping.SupplementServicePrincipalNames = true;

            var result = new CertificateRequestValidationResult(_dbRow);

            var dsObject = _dsObject;
            dsObject.ServicePrincipalNames.Add("HOST/this-is-1-test.tamemycerts-tests.com");
            dsObject.ServicePrincipalNames.Add("TERMSRV/this-is-2-test.tamemycerts-tests.com");
            dsObject.ServicePrincipalNames.Add("HTTP/this-is-3-test.tamemycerts-tests.com");
            dsObject.ServicePrincipalNames.Add("WSMAN/this-is-4-test.tamemycerts-tests.com");

            // this one is not a valid DNS name and thus shall be omitted
            dsObject.ServicePrincipalNames.Add("WSMAN/this-is-5-test.tamemycerts-tests.com/something");

            result = _validator.VerifyRequest(result, policy, dsObject);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
            Assert.IsTrue(
                result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
                Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                    .Equals(expectedResult));
        }

        [TestMethod]
        public void Does_not_supplement_spn_if_none_present()
        {
            const string expectedResult = "MCaCJHRoaXMtaXMtYS10ZXN0LnRhbWVteWNlcnRzLXRlc3RzLmNvbQ==";

            var policy = _policy;
            policy.DirectoryServicesMapping.SupplementServicePrincipalNames = true;

            var result = new CertificateRequestValidationResult(_dbRow);

            result.SubjectAlternativeNameExtension.AddDnsName("this-is-a-test.tamemycerts-tests.com");

            result = _validator.VerifyRequest(result, policy, _dsObject);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
            Assert.IsTrue(
                result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
                Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                    .Equals(expectedResult));
        }

        [TestMethod]
        public void Allow_if_whitelisted_pattern_does_match()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.DirectoryObjectRules.Add(new DirectoryObjectRule
            {
                Patterns = new List<Pattern>
                {
                    new Pattern
                    {
                        Expression = "^.*$"
                    }
                }
            });

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Allow_if_non_mandatory_attribute_missing()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.DirectoryObjectRules.Add(new DirectoryObjectRule
            {
                DirectoryServicesAttribute = "thisisnotpresent",
                Patterns = new List<Pattern>
                {
                    new Pattern
                    {
                        Expression = "^.*$"
                    }
                }
            });

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Deny_if_mandatory_attribute_missing()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.DirectoryObjectRules.Add(new DirectoryObjectRule
            {
                DirectoryServicesAttribute = "thisisnotpresent",
                Mandatory = true,
                Patterns = new List<Pattern>
                {
                    new Pattern
                    {
                        Expression = "^.*$"
                    }
                }
            });

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_if_whitelisted_pattern_does_not_match()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.DirectoryObjectRules.Add(new DirectoryObjectRule
            {
                Patterns = new List<Pattern>
                {
                    new Pattern
                    {
                        Expression = "^notrudi$"
                    }
                }
            });

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_if_blacklisted_pattern_does_match()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.DirectoryObjectRules.Add(new DirectoryObjectRule
            {
                Patterns = new List<Pattern>
                {
                    new Pattern
                    {
                        Expression = "^rudi$",
                        Action = "Deny"
                    }
                }
            });

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_if_both_whitelisted_and_blacklisted_pattern_do_match()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.DirectoryObjectRules.Add(new DirectoryObjectRule
            {
                Patterns = new List<Pattern>
                {
                    new Pattern
                    {
                        Expression = "^rudi$"
                    },
                    new Pattern
                    {
                        Expression = "^rudi$",
                        Action = "Deny"
                    }
                }
            });

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Allow_if_object_in_whitelisted_OU()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.AllowedOrganizationalUnits.Add(
                "OU=Test-Users,DC=intra,DC=adcslabor,DC=de");

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Allow_if_object_in_whitelisted_nested_OU()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.AllowedOrganizationalUnits.Add(
                "DC=intra,DC=adcslabor,DC=de");

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }

        [TestMethod]
        public void Deny_if_object_not_in_whitelisted_OU()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.AllowedOrganizationalUnits.Add(
                "OU=Super-Users,DC=intra,DC=adcslabor,DC=de");

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_if_object_in_blacklisted_OU()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.DisallowedOrganizationalUnits.Add(
                "OU=Test-Users,DC=intra,DC=adcslabor,DC=de");

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_if_object_in_blacklisted_nested_OU()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.DisallowedOrganizationalUnits.Add(
                "DC=intra,DC=adcslabor,DC=de");

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Deny_if_object_both_in_whitelisted_and_blacklisted_OU()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.AllowedOrganizationalUnits.Add("DC=intra,DC=adcslabor,DC=de");
            policy.DirectoryServicesMapping.DisallowedOrganizationalUnits.Add(
                "OU=Test-Users,DC=intra,DC=adcslabor,DC=de");

            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            // TODO
            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }

        [TestMethod]
        public void Allow_if_user_password_age_is_good()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.MaximumPasswordAge = 30;
            ActiveDirectoryObject dsObject = _dsObject;
            dsObject.Attributes.Add("pwdLastSet", DateTime.Now.AddMinutes(-15).ToFileTimeUtc().ToString());
            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        }
        [TestMethod]
        public void Deny_if_user_passwordchange_is_too_close()
        {
            var policy = _policy;
            var result = new CertificateRequestValidationResult(_dbRow);

            policy.DirectoryServicesMapping.MaximumPasswordAge = 30;
            ActiveDirectoryObject dsObject = _dsObject;
            dsObject.Attributes.Add("pwdLastSet", DateTime.Now.AddMinutes(-45).ToFileTimeUtc().ToString());
            result = _validator.VerifyRequest(result, policy, _dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
            Assert.IsTrue(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        }
    }
}