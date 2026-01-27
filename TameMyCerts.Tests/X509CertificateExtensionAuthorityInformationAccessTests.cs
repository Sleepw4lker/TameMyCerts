using System;
using TameMyCerts.X509;
using Xunit;
using Xunit.Abstractions;

namespace TameMyCerts.Tests;

public class X509CertificateExtensionAuthorityInformationAccessTests(ITestOutputHelper output)
{
    [Fact]
    public void Building_long()
    {
        const string expectedResult =
            "MIIBLDCBrgYIKwYBBQUHMAKGgaFsZGFwOi8vL0NOPVRFU1QtQ0EsQ049QUlBLENO" +
            "PVB1YmxpYyBLZXkgU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv" +
            "bixEQz10YW1lbXljZXJ0cy10ZXN0cyxEQz1sb2NhbD9jQUNlcnRpZmljYXRlP2Jh" +
            "c2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTBDBggrBgEFBQcw" +
            "AoY3aHR0cDovL3BraS50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbC9DZXJ0RGF0YS9U" +
            "RVNULUNBLmNydDA0BggrBgEFBQcwAYYoaHR0cDovL29jc3AudGFtZW15Y2VydHMt" +
            "dGVzdHMubG9jYWwvb2NzcA==";

        var aiaExt = new X509CertificateExtensionAuthorityInformationAccess();

        aiaExt.AddUniformResourceIdentifier(
            "ldap:///CN=TEST-CA,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration," +
            "DC=tamemycerts-tests,DC=local?cACertificate?base?objectClass=certificationAuthority"
        );
        aiaExt.AddUniformResourceIdentifier("http://pki.tamemycerts-tests.local/CertData/TEST-CA.crt");
        aiaExt.AddUniformResourceIdentifier("http://ocsp.tamemycerts-tests.local/ocsp", true);

        aiaExt.InitializeEncode();

        output.WriteLine(Convert.ToBase64String(aiaExt.RawData));

        Assert.Equal(expectedResult, Convert.ToBase64String(aiaExt.RawData));
    }

    [Fact]
    public void Building_short()
    {
        const string expectedResult =
            "MEUwQwYIKwYBBQUHMAKGN2h0dHA6Ly9wa2kudGFtZW15Y2VydHMtdGVzdHMubG9j" +
            "YWwvQ2VydERhdGEvVEVTVC1DQS5jcnQ=";

        var aiaExt = new X509CertificateExtensionAuthorityInformationAccess();

        aiaExt.AddUniformResourceIdentifier("http://pki.tamemycerts-tests.local/CertData/TEST-CA.crt");
        aiaExt.InitializeEncode();

        output.WriteLine(Convert.ToBase64String(aiaExt.RawData));

        Assert.Equal(expectedResult, Convert.ToBase64String(aiaExt.RawData));
    }

    [Fact]
    public void AddUniformResourceIdentifier_String_Null_ThrowsArgumentNullException()
    {
        var aiaExt = new X509CertificateExtensionAuthorityInformationAccess();
        Assert.Throws<ArgumentNullException>(() => aiaExt.AddUniformResourceIdentifier((string)null));
    }

    [Fact]
    public void AddUniformResourceIdentifier_Uri_Null_ThrowsArgumentNullException()
    {
        var aiaExt = new X509CertificateExtensionAuthorityInformationAccess();
        Assert.Throws<ArgumentNullException>(() => aiaExt.AddUniformResourceIdentifier((Uri)null));
    }
}