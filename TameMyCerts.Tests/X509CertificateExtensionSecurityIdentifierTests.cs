using System;
using System.Security.Principal;
using TameMyCerts.X509;
using Xunit;

namespace TameMyCerts.Tests;

public class X509CertificateExtensionSecurityIdentifierTests
{
    [Fact]
    public void Building()
    {
        const string expectedResult =
            "MD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMzgxMTg2MDUyLTQyNDc2OTIz" +
            "ODYtMTM1OTI4MDc4LTEyMjU=";

        const string sid = "S-1-5-21-1381186052-4247692386-135928078-1225";

        var sidExt = new X509CertificateExtensionSecurityIdentifier(new SecurityIdentifier(sid));

        Assert.Equal(expectedResult, Convert.ToBase64String(sidExt.RawData));
    }
}