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
using System.Security.Principal;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts;

namespace UnitTests
{
    [TestClass]
    public class DirectoryServicesValidatorTests
    {
        private readonly DirectoryServicesValidator _directoryServicesValidator = new DirectoryServicesValidator(true);
        private readonly ActiveDirectoryObject _dsObject;
        private readonly CertificateRequestPolicy _requestPolicy;

        private readonly CertificateRequestValidationResult
            _validationResult = new CertificateRequestValidationResult();

        public DirectoryServicesValidatorTests()
        {
            _dsObject = new ActiveDirectoryObject(
                "rudi@intra.adcslabor.de",
                0,
                new List<string> {"CN=PKI_UserCert,OU=ADCSLabor Gruppen,DC=intra,DC=adcslabor,DC=de"},
                new Dictionary<string, string>
                {
                    {"c", "DE"},
                    {"company", "ADCS Labor"},
                    {"displayName", "Rudi Ratlos"},
                    {"department", "IT Operations"},
                    {"givenName", "Rudi"},
                    {"initials", "RR"},
                    {"l", "München"},
                    {"mail", "rudi@adcslabor.de"},
                    {"name", "rudi"},
                    {"sAMAccountName", "DE"},
                    {"sn", "Ratlos"},
                    {"st", "Bavaria"},
                    // Note that streetAddress is left out intentionally
                    {"title", "General Manager"},
                    {"userPrincipalName", "rudi@intra.adcslabor.de"}
                },
                new SecurityIdentifier("S-1-5-21-1381186052-4247692386-135928078-1225")
            );

            _requestPolicy = new CertificateRequestPolicy
            {
                DirectoryServicesMapping = new DirectoryServicesMapping
                {
                    AllowedSecurityGroups = new List<string>
                        {"CN=PKI_UserCert,OU=ADCSLabor Gruppen,DC=intra,DC=adcslabor,DC=de"},
                    SubjectDistinguishedName = new List<RelativeDistinguishedName>
                    {
                        new RelativeDistinguishedName
                        {
                            Field = "commonName",
                            DirectoryServicesAttribute = "userPrincipalName",
                            Mandatory = true
                        }
                    }
                },
                SecurityIdentifierExtension = "Add"
            };
        }

        public void PrintResult(CertificateRequestValidationResult validationResult)
        {
            Console.WriteLine("0x{0:X} ({0}) {1}.", validationResult.StatusCode,
                new Win32Exception(validationResult.StatusCode).Message);
            Console.WriteLine(string.Join("\n", validationResult.Description));
        }

        [TestMethod]
        public void Allow_disabled_account_when_set()
        {
            var requestPolicy = _requestPolicy;
            var result = _validationResult;
            var dsObject = _dsObject;

            dsObject.UserAccountControl = UserAccountControl.ACCOUNTDISABLE;
            requestPolicy.DirectoryServicesMapping.PermitDisabledAccounts = true;

            result = _directoryServicesValidator.VerifyRequest(requestPolicy, result, dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Deny_disabled_account()
        {
            var result = _validationResult;
            var dsObject = _dsObject;

            dsObject.UserAccountControl = UserAccountControl.ACCOUNTDISABLE;

            result = _directoryServicesValidator.VerifyRequest(_requestPolicy, result, dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Allow_if_member_of_allowed_group()
        {
            var result = _validationResult;

            result = _directoryServicesValidator.VerifyRequest(_requestPolicy, result, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Deny_if_not_member_of_any_allowed_group()
        {
            var result = _validationResult;
            var dsObject = _dsObject;

            dsObject.MemberOf.Clear();

            result = _directoryServicesValidator.VerifyRequest(_requestPolicy, result, dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Deny_if_member_of_forbidden_group()
        {
            var requestPolicy = _requestPolicy;
            var result = _validationResult;
            var dsObject = _dsObject;

            dsObject.MemberOf.Add("test");
            requestPolicy.DirectoryServicesMapping.DisallowedSecurityGroups.Add("test");

            result = _directoryServicesValidator.VerifyRequest(requestPolicy, result, dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Allow_and_add_directory_attribute()
        {
            var result = _validationResult;
            result = _directoryServicesValidator.VerifyRequest(_requestPolicy, result, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.Properties.ContainsKey("Subject.CommonName") &&
                          result.Properties["Subject.CommonName"].Equals("rudi@intra.adcslabor.de"));
        }

        [TestMethod]
        public void Deny_if_unable_to_add_nonpresent_mandatory_attribute()
        {
            var requestPolicy = _requestPolicy;
            var result = _validationResult;

            requestPolicy.DirectoryServicesMapping.SubjectDistinguishedName.Add(new RelativeDistinguishedName
            {
                Field = "streetAddress",
                DirectoryServicesAttribute = "streetAddress",
                Mandatory = true
            });

            result = _directoryServicesValidator.VerifyRequest(requestPolicy, result, _dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Deny_if_attribute_too_long()
        {
            var requestPolicy = _requestPolicy;
            var result = _validationResult;
            var dsObject = _dsObject;

            requestPolicy.DirectoryServicesMapping.SubjectDistinguishedName.Add(new RelativeDistinguishedName
            {
                Field = "countryName",
                DirectoryServicesAttribute = "c",
                Mandatory = true
            });

            dsObject.Attributes["c"] = "test";

            result = _directoryServicesValidator.VerifyRequest(requestPolicy, result, dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Deny_if_attribute_unknown()
        {
            var requestPolicy = _requestPolicy;
            var result = _validationResult;
            var dsObject = _dsObject;

            requestPolicy.DirectoryServicesMapping.SubjectDistinguishedName.Add(new RelativeDistinguishedName
            {
                Field = "test",
                DirectoryServicesAttribute = "c",
                Mandatory = true
            });

            result = _directoryServicesValidator.VerifyRequest(requestPolicy, result, dsObject);

            PrintResult(result);

            Assert.IsTrue(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Allow_but_dont_add_if_attribute_unknown()
        {
            var requestPolicy = _requestPolicy;
            var result = _validationResult;
            var dsObject = _dsObject;

            requestPolicy.DirectoryServicesMapping.SubjectDistinguishedName.Add(new RelativeDistinguishedName
            {
                Field = "test",
                DirectoryServicesAttribute = "c"
            });

            result = _directoryServicesValidator.VerifyRequest(requestPolicy, result, dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
        }

        [TestMethod]
        public void Allow_but_dont_add_if_attribute_too_long()
        {
            var requestPolicy = _requestPolicy;
            var result = _validationResult;
            var dsObject = _dsObject;

            requestPolicy.DirectoryServicesMapping.SubjectDistinguishedName.Add(new RelativeDistinguishedName
            {
                Field = "countryName",
                DirectoryServicesAttribute = "c"
            });

            dsObject.Attributes["c"] = "test";

            result = _directoryServicesValidator.VerifyRequest(requestPolicy, result, dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsFalse(result.Properties.ContainsKey("Subject.Country"));
        }

        [TestMethod]
        public void Allow_and_add_SID_extension_if_configured()
        {
            const string expectedSecurityIdentifier =
                "MD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMzgxMTg2MDUyLTQyNDc2OTIzODYtMTM1OTI4MDc4LTEyMjU=";

            var result = _validationResult;
            result = _directoryServicesValidator.VerifyRequest(_requestPolicy, result, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.Extensions.ContainsKey(WinCrypt.szOID_DS_CA_SECURITY_EXT) &&
                          result.Extensions[WinCrypt.szOID_DS_CA_SECURITY_EXT].Equals(expectedSecurityIdentifier));
        }

        [TestMethod]
        public void Allow_but_dont_add_SID_extension_if_allowed()
        {
            var requestPolicy = _requestPolicy;
            var result = _validationResult;

            requestPolicy.SecurityIdentifierExtension = "Allow";

            result = _directoryServicesValidator.VerifyRequest(requestPolicy, result, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsFalse(result.Extensions.ContainsKey(WinCrypt.szOID_DS_CA_SECURITY_EXT));
        }

        [TestMethod]
        public void Allow_but_dont_add_SID_extension_if_denied()
        {
            var requestPolicy = _requestPolicy;
            var result = _validationResult;

            requestPolicy.SecurityIdentifierExtension = "Deny";

            result = _directoryServicesValidator.VerifyRequest(requestPolicy, result, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsFalse(result.Extensions.ContainsKey(WinCrypt.szOID_DS_CA_SECURITY_EXT));
        }
    }
}