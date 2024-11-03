using System;
using TameMyCerts.X509;
using Xunit;

namespace TameMyCerts.Tests;

public class X509CertificateExtensionOcspMustStapleTests
{
    [Fact]
    public void Building()
    {
        const string expectedResult = "MAMCAQU=";

        var ocspStaplingExt = new X509CertificateExtensionOcspMustStaple();

        Assert.True(Convert.ToBase64String(ocspStaplingExt.RawData).Equals(expectedResult));
    }
}