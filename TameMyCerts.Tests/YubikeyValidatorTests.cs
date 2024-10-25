using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Principal;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;

namespace TameMyCerts.Tests
{
    [TestClass]
    public class YubikeyValidatorTests
    {
        private readonly CertificateDatabaseRow _dbRow;
        private readonly CertificateRequestPolicy _policy;
        private readonly YubikeyValidator _YKvalidator = new YubikeyValidator();
        private readonly CertificateContentValidator _CCvalidator = new CertificateContentValidator();
        private readonly CertificateAuthorityConfiguration _caConfig;

        public YubikeyValidatorTests()
        {
            // Sample CSR from a Yubikey with attestion included
            var request =
                "-----BEGIN CERTIFICATE REQUEST-----\n" +
"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\n" +
"Oq0a7fphvaY3PqAsU4JOFVw55ukrXnUSof+z\n" +
"-----END CERTIFICATE REQUEST-----\n";


             _policy = new CertificateRequestPolicy {
                 YubikeyPolicy = new YubikeyPolicy
                 {
                            AllowedPinPolicies = new List<string>
                                    { "Always" }
                        }
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
        public void Extract_Genuine_Yubikey_Attestion()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            result = _YKvalidator.ExtractAttestion(result, _policy, _dbRow, out var yubikey);

            Assert.IsTrue(yubikey.TouchPolicy == "Never");
            Assert.IsTrue(yubikey.PinPolicy == "Once");
            Assert.IsTrue(yubikey.FirmwareVersion.ToString() == "5.4.3");
            Assert.IsTrue(yubikey.FormFactor == "UsbAKeychain");
            Assert.IsTrue(yubikey.Slot == "9a");
            PrintResult(result);

        }

        [TestMethod]
        public void Validate_Policy_Firmware_Disallow_5_4_3()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            result = _YKvalidator.ExtractAttestion(result, _policy, _dbRow, out var yubikey);
            
            CertificateRequestPolicy policy = new CertificateRequestPolicy
            {
                YubikeyPolicy = new YubikeyPolicy
                {
                    DisallowedFirmwareVersion = new List<string>
                                    { "5.4.3" }
                }
            };

            result = _YKvalidator.VerifyRequest(result, policy, yubikey);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }
        [TestMethod]
        public void Validate_Policy_Firmware_Allowed_5_7_1()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            result = _YKvalidator.ExtractAttestion(result, _policy, _dbRow, out var yubikey);

            CertificateRequestPolicy policy = new CertificateRequestPolicy
            {
                YubikeyPolicy = new YubikeyPolicy
                {
                    AllowedFirmwareVersion = new List<string>
                                    { "5.7.1" }
                }
            };

            result = _YKvalidator.VerifyRequest(result, policy, yubikey);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }
        [TestMethod]
        public void Validate_PIN_Policy_Disallowed_Once_correct()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            result = _YKvalidator.ExtractAttestion(result, _policy, _dbRow, out var yubikey);

            CertificateRequestPolicy policy = new CertificateRequestPolicy
            {
                YubikeyPolicy = new YubikeyPolicy
                {
                    DisallowedPinPolicies = new List<string>
                                    { "Once" }
                }
            };

            result = _YKvalidator.VerifyRequest(result, policy, yubikey);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }
        [TestMethod]
        public void Validate_PIN_Policy_Allowed_Never_incorrect()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            result = _YKvalidator.ExtractAttestion(result, _policy, _dbRow, out var yubikey);

            CertificateRequestPolicy policy = new CertificateRequestPolicy
            {
                YubikeyPolicy = new YubikeyPolicy
                {
                    AllowedPinPolicies = new List<string>
                                    { "Never" }
                }
            };

            result = _YKvalidator.VerifyRequest(result, policy, yubikey);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Validate_PIN_Policy_Allowed_Once_correct()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            result = _YKvalidator.ExtractAttestion(result, _policy, _dbRow, out var yubikey);

            CertificateRequestPolicy policy = new CertificateRequestPolicy
            {
                YubikeyPolicy = new YubikeyPolicy
                {
                    AllowedPinPolicies = new List<string>
                                    { "Once" }
                }
            };

            result = _YKvalidator.VerifyRequest(result, policy, yubikey);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
        }
        [TestMethod]
        public void Validate_Touch_Policy_Disallowed_Never_correct()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            result = _YKvalidator.ExtractAttestion(result, _policy, _dbRow, out var yubikey);

            CertificateRequestPolicy policy = new CertificateRequestPolicy
            {
                YubikeyPolicy = new YubikeyPolicy
                {
                    DisallowedTouchPolicies = new List<string>
                                    { "Never" }
                }
            };

            result = _YKvalidator.VerifyRequest(result, policy, yubikey);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }
        [TestMethod]
        public void Validate_Touch_Policy_Allowed_Always_incorrect()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            result = _YKvalidator.ExtractAttestion(result, _policy, _dbRow, out var yubikey);

            CertificateRequestPolicy policy = new CertificateRequestPolicy
            {
                YubikeyPolicy = new YubikeyPolicy
                {
                    AllowedTouchPolicies = new List<string>
                                    { "Always" }
                }
            };

            result = _YKvalidator.VerifyRequest(result, policy, yubikey);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Validate_Touch_Policy_Allowed_Never_correct()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            result = _YKvalidator.ExtractAttestion(result, _policy, _dbRow, out var yubikey);

            CertificateRequestPolicy policy = new CertificateRequestPolicy
            {
                YubikeyPolicy = new YubikeyPolicy
                {
                    AllowedTouchPolicies = new List<string>
                                    { "Never" }
                }
            };

            result = _YKvalidator.VerifyRequest(result, policy, yubikey);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
        }


        [TestMethod]
        public void Rewrite_Subject_to_slot()
        {
            var result = new CertificateRequestValidationResult(_dbRow);
            result = _YKvalidator.ExtractAttestion(result, _policy, _dbRow, out var yubikey);

            CertificateRequestPolicy policy = new CertificateRequestPolicy
            {
                YubikeyPolicy = new YubikeyPolicy
                {
                },
                OutboundSubject = new List<OutboundSubjectRule>
                {
                    new OutboundSubjectRule
                    {
                        Field = RdnTypes.CommonName,
                        Value = "{yk:slot}",
                        Mandatory = true,
                        Force = true
                    }
                }
            };

            result = _YKvalidator.VerifyRequest(result, policy, yubikey);
            result = _CCvalidator.VerifyRequest(result, policy, _dbRow, null, _caConfig, yubikey);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.CertificateProperties
    .Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.CommonName]))
    .Any(x => x.Value.Equals("9a"))
);
        }
    }
}