using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.X509;

namespace TameMyCerts.Tests
{
    [TestClass]
    public class X509CertificateExtensionOcspMustStapleTests
    {
        [TestMethod]
        public void Building()
        {
            const string expectedResult = "MAMCAQU=";

            var ocspStaplingExt = new X509CertificateExtensionOcspMustStaple();

            Assert.IsTrue(Convert.ToBase64String(ocspStaplingExt.RawData).Equals(expectedResult));
        }
    }
}