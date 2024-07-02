using System;
using System.Net;
using System.Net.Mail;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.Models;
using TameMyCerts.X509;

namespace TameMyCerts.Tests
{
    [TestClass]
    public class X509CertificateExtensionSubjectAlternativeNameTests
    {
        [TestMethod]
        public void Does_not_build_with_invalid_string_input()
        {
            Assert.ThrowsException<COMException>(() =>
                new X509CertificateExtensionSubjectAlternativeName("invalid"));
        }

        [TestMethod]
        public void Does_not_build_with_invalid_binary_input()
        {
            Assert.ThrowsException<COMException>(() =>
                new X509CertificateExtensionSubjectAlternativeName(new byte[] { 0x1, 0x2, 0x3, 0x4 }));
        }

        [TestMethod]
        public void Builds_with_empty_content()
        {
            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.InitializeEncode();

            Assert.IsTrue(sanExt.RawData.Equals(Array.Empty<byte>()));
            Assert.IsTrue(sanExt.AlternativeNames.Count.Equals(0));
        }

        [TestMethod]
        public void Builds_with_empty_string_input()
        {
            var sanExt = new X509CertificateExtensionSubjectAlternativeName(string.Empty);
            sanExt.InitializeEncode();

            Assert.IsTrue(sanExt.RawData.Equals(Array.Empty<byte>()));
            Assert.IsTrue(sanExt.AlternativeNames.Count.Equals(0));
        }

        [TestMethod]
        public void Builds_with_empty_binary_input()
        {
            var sanExt = new X509CertificateExtensionSubjectAlternativeName(Array.Empty<byte>());
            sanExt.InitializeEncode();

            Assert.IsTrue(sanExt.RawData.Equals(Array.Empty<byte>()));
            Assert.IsTrue(sanExt.AlternativeNames.Count.Equals(0));
        }

        [TestMethod]
        public void Builds_one_Uri_with_SID()
        {
            const string expectedResult =
                "MFCGTnRhZzptaWNyb3NvZnQuY29tLDIwMjItMDktMTQ6c2lkOlMtMS01LTIxLTEzODExODYwNTItNDI0NzY5MjM4Ni0xMzU5MjgwNzgtMTIyNQ==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddUniformResourceIdentifier(
                "tag:microsoft.com,2022-09-14:sid:S-1-5-21-1381186052-4247692386-135928078-1225");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Builds_one_dNSName()
        {
            const string expectedResult = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddDnsName("some-test.tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Builds_one_iPAddress()
        {
            const string expectedResult = "MAaHBMCoAAE=";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddIpAddress(IPAddress.Parse("192.168.0.1"));
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Builds_one_userPrincipalName()
        {
            const string expectedResult =
                "MDegNQYKKwYBBAGCNxQCA6AnDCVBZG1pbmlzdHJhdG9yQHRhbWVteWNlcnRzLXRlc3RzLmxvY2Fs";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddUserPrincipalName("Administrator@tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Builds_one_rfc822Name()
        {
            const string expectedResult = "MCeBJUFkbWluaXN0cmF0b3JAdGFtZW15Y2VydHMtdGVzdHMubG9jYWw=";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddEmailAddress(new MailAddress("Administrator@tamemycerts-tests.local"));
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Builds_one_rfc822Name_from_string()
        {
            const string expectedResult = "MCeBJUFkbWluaXN0cmF0b3JAdGFtZW15Y2VydHMtdGVzdHMubG9jYWw=";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddEmailAddress("Administrator@tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Builds_one_uniformResourceIdentifier()
        {
            const string expectedResult = "MCuGKWh0dHA6Ly9zb21lLXRlc3QudGFtZW15Y2VydHMtdGVzdHMubG9jYWwv";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();

            sanExt.AddUniformResourceIdentifier(new Uri("http://some-test.tamemycerts-tests.local/"));
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Builds_one_uniformResourceIdentifier_from_string()
        {
            const string expectedResult = "MCuGKWh0dHA6Ly9zb21lLXRlc3QudGFtZW15Y2VydHMtdGVzdHMubG9jYWwv";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();

            sanExt.AddUniformResourceIdentifier("http://some-test.tamemycerts-tests.local/");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Builds_empty_when_all_are_removed()
        {
            const string rawData = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.RemoveDnsName("some-test.tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(sanExt.RawData.Equals(Array.Empty<byte>()));
        }

        [TestMethod]
        public void Decodes_one_dNSName()
        {
            const string rawData = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);

            Assert.IsTrue(sanExt.AlternativeNames[0].Key == SanTypes.DnsName);
            Assert.IsTrue(sanExt.AlternativeNames[0].Value == "some-test.tamemycerts-tests.local");
        }

        [TestMethod]
        public void Decodes_one_iPAddress()
        {
            const string rawData = "MAaHBMCoAAE=";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);

            Assert.IsTrue(sanExt.AlternativeNames[0].Key == SanTypes.IpAddress);
            Assert.IsTrue(sanExt.AlternativeNames[0].Value == "192.168.0.1");
        }

        [TestMethod]
        public void Decodes_one_userPrincipalName()
        {
            const string rawData = "MDegNQYKKwYBBAGCNxQCA6AnDCVBZG1pbmlzdHJhdG9yQHRhbWVteWNlcnRzLXRlc3RzLmxvY2Fs";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);

            Assert.IsTrue(sanExt.AlternativeNames[0].Key == SanTypes.UserPrincipalName);
            Assert.IsTrue(sanExt.AlternativeNames[0].Value == "Administrator@tamemycerts-tests.local");
        }

        [TestMethod]
        public void Decodes_one_rfc822Name()
        {
            const string rawData = "MCeBJUFkbWluaXN0cmF0b3JAdGFtZW15Y2VydHMtdGVzdHMubG9jYWw=";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);

            Assert.IsTrue(sanExt.AlternativeNames[0].Key == SanTypes.Rfc822Name);
            Assert.IsTrue(sanExt.AlternativeNames[0].Value == "Administrator@tamemycerts-tests.local");
        }

        [TestMethod]
        public void Decodes_one_uniformResourceIdentifier()
        {
            const string rawData = "MCuGKWh0dHA6Ly9zb21lLXRlc3QudGFtZW15Y2VydHMtdGVzdHMubG9jYWwv";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);

            Assert.IsTrue(sanExt.AlternativeNames[0].Key == SanTypes.UniformResourceIdentifier);
            Assert.IsTrue(sanExt.AlternativeNames[0].Value == "http://some-test.tamemycerts-tests.local/");
        }

        [TestMethod]
        public void Does_not_add_same_dNSName()
        {
            const string expectedResult = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddDnsName("some-test.tamemycerts-tests.local");
            sanExt.AddDnsName("some-test.tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Does_not_add_invalid_Type()
        {
            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddAlternativeName("thisisnotvalid", "some-test.tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(sanExt.RawData.Equals(Array.Empty<byte>()));
        }

        [TestMethod]
        public void Does_not_add_invalid_dNSName()
        {
            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddAlternativeName(SanTypes.DnsName, "thisisnotvalid!?");
            sanExt.InitializeEncode();

            Assert.IsTrue(sanExt.RawData.Equals(Array.Empty<byte>()));
        }

        [TestMethod]
        public void Does_not_add_invalid_ipAddress()
        {
            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddAlternativeName(SanTypes.IpAddress, "thisisnotvalid!?");
            sanExt.InitializeEncode();

            Assert.IsTrue(sanExt.RawData.Equals(Array.Empty<byte>()));
        }

        [TestMethod]
        public void Does_not_add_invalid_userPrincipalName()
        {
            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddAlternativeName(SanTypes.UserPrincipalName, "thisisnotvalid!?");
            sanExt.InitializeEncode();

            Assert.IsTrue(sanExt.RawData.Equals(Array.Empty<byte>()));
        }

        [TestMethod]
        public void Does_not_add_invalid_rfc822Name()
        {
            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddAlternativeName(SanTypes.Rfc822Name, "thisisnotvalid!?");
            sanExt.InitializeEncode();

            Assert.IsTrue(sanExt.RawData.Equals(Array.Empty<byte>()));
        }

        [TestMethod]
        public void Does_not_add_invalid_uniformResourceIdentifier()
        {
            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddAlternativeName(SanTypes.UniformResourceIdentifier, "thisisnotvalid!?");
            sanExt.InitializeEncode();

            Assert.IsTrue(sanExt.RawData.Equals(Array.Empty<byte>()));
        }

        [TestMethod]
        public void Does_not_add_same_iPAddress()
        {
            const string expectedResult = "MAaHBMCoAAE=";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddIpAddress(IPAddress.Parse("192.168.0.1"));
            sanExt.AddIpAddress(IPAddress.Parse("192.168.0.1"));
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Does_not_add_same_userPrincipalName()
        {
            const string expectedResult =
                "MDegNQYKKwYBBAGCNxQCA6AnDCVBZG1pbmlzdHJhdG9yQHRhbWVteWNlcnRzLXRlc3RzLmxvY2Fs";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddUserPrincipalName("Administrator@tamemycerts-tests.local");
            sanExt.AddUserPrincipalName("Administrator@tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Does_not_add_same_rfc822Name()
        {
            const string expectedResult = "MCeBJUFkbWluaXN0cmF0b3JAdGFtZW15Y2VydHMtdGVzdHMubG9jYWw=";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddEmailAddress(new MailAddress("Administrator@tamemycerts-tests.local"));
            sanExt.AddEmailAddress(new MailAddress("Administrator@tamemycerts-tests.local"));
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Does_not_add_same_uniformResourceIdentifier()
        {
            const string expectedResult = "MCuGKWh0dHA6Ly9zb21lLXRlc3QudGFtZW15Y2VydHMtdGVzdHMubG9jYWwv";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.AddUniformResourceIdentifier(new Uri("http://some-test.tamemycerts-tests.local/"));
            sanExt.AddUniformResourceIdentifier(new Uri("http://some-test.tamemycerts-tests.local/"));
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Adds_one_dNSName()
        {
            const string rawData = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";
            const string expectedResult =
                "MEmCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbIIkYW5vdGhlci10ZXN0LnRhbWVteWNlcnRzLXRlc3RzLmxvY2Fs";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.AddDnsName("another-test.tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Adds_one_uniformResourceIdentifier()
        {
            const string rawData = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";
            const string expectedResult =
                "ME6CIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbIYpaHR0cDovL3NvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbC8=";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.AddUniformResourceIdentifier("http://some-test.tamemycerts-tests.local/");
            sanExt.InitializeEncode();

            Console.WriteLine(Convert.ToBase64String(sanExt.RawData));

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Adds_one_rfc822Name()
        {
            const string rawData = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";
            const string expectedResult =
                "MEqCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbIElQWRtaW5pc3RyYXRvckB0YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.AddEmailAddress(new MailAddress("Administrator@tamemycerts-tests.local"));
            sanExt.InitializeEncode();

            Console.WriteLine(Convert.ToBase64String(sanExt.RawData));

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Adds_one_userPrincipalName()
        {
            const string rawData = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";
            const string expectedResult =
                "MFqCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbKA1BgorBgEEAYI3FAIDoCcMJUFkbWluaXN0cmF0b3JAdGFtZW15Y2VydHMtdGVzdHMubG9jYWw=";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.AddUserPrincipalName("Administrator@tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Console.WriteLine(Convert.ToBase64String(sanExt.RawData));

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Adds_one_iPAddress()
        {
            const string rawData = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";
            const string expectedResult = "MCmCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbIcEwKgAAQ==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.AddIpAddress(IPAddress.Parse("192.168.0.1"));
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Removes_one_dNSName()
        {
            const string rawData =
                "MEmCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbIIkYW5vdGhlci10ZXN0LnRhbWVteWNlcnRzLXRlc3RzLmxvY2Fs";
            const string expectedResult = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.RemoveDnsName("another-test.tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Removes_one_iPAddress()
        {
            const string rawData = "MCmCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbIcEwKgAAQ==";
            const string expectedResult = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.RemoveIpAddress(IPAddress.Parse("192.168.0.1"));
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Removes_one_uniformResourceIdentifier()
        {
            const string rawData =
                "ME6CIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbIYpaHR0cDovL3NvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbC8=";
            const string expectedResult = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.RemoveUniformResourceIdentifier(new Uri("http://some-test.tamemycerts-tests.local/"));
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Removes_one_uniformResourceIdentifier_from_string()
        {
            const string rawData =
                "ME6CIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbIYpaHR0cDovL3NvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbC8=";
            const string expectedResult = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.RemoveUniformResourceIdentifier("http://some-test.tamemycerts-tests.local/");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Removes_one_rfc822Name()
        {
            const string rawData =
                "MEqCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbIElQWRtaW5pc3RyYXRvckB0YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";
            const string expectedResult = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.RemoveEmailAddress(new MailAddress("Administrator@tamemycerts-tests.local"));
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Removes_one_rfc822Name_from_string()
        {
            const string rawData =
                "MEqCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbIElQWRtaW5pc3RyYXRvckB0YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";
            const string expectedResult = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.RemoveEmailAddress("Administrator@tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Removes_one_userPrincipalName()
        {
            const string rawData =
                "MFqCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbKA1BgorBgEEAYI3FAIDoCcMJUFkbWluaXN0cmF0b3JAdGFtZW15Y2VydHMtdGVzdHMubG9jYWw=";
            const string expectedResult = "MCOCIXNvbWUtdGVzdC50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbA==";

            var sanExt = new X509CertificateExtensionSubjectAlternativeName(rawData);
            sanExt.RemoveUserPrincipalName("Administrator@tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(sanExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void Does_not_remove_if_empty()
        {
            var sanExt = new X509CertificateExtensionSubjectAlternativeName();
            sanExt.RemoveUserPrincipalName("Administrator@tamemycerts-tests.local");
            sanExt.InitializeEncode();

            Assert.IsTrue(sanExt.RawData.Equals(Array.Empty<byte>()));
        }
    }
}