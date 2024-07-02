using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.X509;

namespace TameMyCerts.Tests
{
    [TestClass]
    public class X509CertificateExtensionAuthorityKeyIdentifierTests
    {
        [TestMethod]
        public void Building()
        {
            var akiBytes = new byte[]
            {
                0x9a, 0x52, 0x0b, 0x89, 0x71, 0xaa, 0x4d, 0x9e, 0x32, 0x6e, 0x94, 0xd0, 0x8b, 0x99, 0x85, 0x4b, 0xb7,
                0x31, 0x1d, 0xc2
            };

            var expectedResult = "MBaAFJpSC4lxqk2eMm6U0IuZhUu3MR3C";

            var akiExt = new X509CertificateExtensionAuthorityKeyIdentifier(akiBytes);

            Assert.IsTrue(Convert.ToBase64String(akiExt.RawData).Equals(expectedResult));
        }
    }
}