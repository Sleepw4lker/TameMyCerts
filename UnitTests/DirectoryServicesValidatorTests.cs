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
        private readonly ActiveDirectoryObject _dsObject;
        private readonly DirectoryServicesValidator _directoryServicesValidator = new DirectoryServicesValidator(true);
        private readonly CertificateRequestPolicy _requestPolicy;
        private readonly CertificateRequestValidationResult _validationResult = new CertificateRequestValidationResult();

        public DirectoryServicesValidatorTests()
        {
            var name = "rudi@intra.adcslabor.de";
            var userAccountControl = 0;
            var memberOf = new List<string> {"CN=PKI_UserCert,OU=ADCSLabor Gruppen,DC=intra,DC=adcslabor,DC=de"};
            var attributes = new Dictionary<string, string>
            {
                {"c", "DE"},
                {"l", "München"},
                {"company", "ADCS Labor"},
                {"displayName", "Rudi Ratlos"},
                {"department", "IT Operations"},
                {"givenName", "Rudi"},
                {"initials", "RR"},
                {"mail", "rudi@adcslabor.de"},
                {"name", "rudi"},
                {"sAMAccountName", "DE"},
                {"sn", "Ratlos"},
                {"st", "Bavaria"},
                // Note that streetAddress is left out intentionally
                {"title", "General Manager"},
                {"userPrincipalName", "rudi@intra.adcslabor.de"}
            };
            var securityIdentifier = new SecurityIdentifier("S-1-5-21-1381186052-4247692386-135928078-1225");

            _dsObject = new ActiveDirectoryObject(name, userAccountControl, memberOf, attributes, securityIdentifier);

            _requestPolicy = new CertificateRequestPolicy
            {
                DirectoryServicesMapping = new DirectoryServicesMapping
                {
                    AllowedSecurityGroups = new List<string> { "CN=PKI_UserCert,OU=ADCSLabor Gruppen,DC=intra,DC=adcslabor,DC=de" },
                    SubjectDistinguishedName = new List<RelativeDistinguishedName>
                    {  
                        new RelativeDistinguishedName
                        {
                            Field = "commonName",
                            DirectoryServicesAttribute = "userPrincipalName",
                            Mandatory = true
                        },
                        new RelativeDistinguishedName
                        {
                            Field = "streetAddress",
                            DirectoryServicesAttribute = "streetAddress"
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
        public void FirstTry()
        {
            const string expectedSecurityIdentifier =
                "MD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMzgxMTg2MDUyLTQyNDc2OTIzODYtMTM1OTI4MDc4LTEyMjU=";

            var result = _validationResult;
            result = _directoryServicesValidator.VerifyRequest(_requestPolicy, result, _dsObject);

            PrintResult(result);

            Assert.IsFalse(result.DeniedForIssuance);
            Assert.IsTrue(result.Properties[0].Key.Equals("Subject.CommonName"));
            Assert.IsTrue(result.Properties[0].Value.Equals("rudi@intra.adcslabor.de"));
            Assert.IsTrue(result.Extensions[0].Value.Equals(expectedSecurityIdentifier));
        }
    }
}