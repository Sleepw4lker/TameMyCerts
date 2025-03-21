using System;
using TameMyCerts.X509;
using Xunit;
using Xunit.Abstractions;

namespace TameMyCerts.Tests;

public class X509CertificateExtensionCrlDistributionPointTests(ITestOutputHelper output)
{
    [Fact]
    public void Building_long()
    {
        const string expectedResult =
            "MIH/MIH8oIH5oIH2hoG6bGRhcDovLy9DTj1URVNULUNBLENOPVRFU1QtU0VSVkVS" +
            "LENOPUNEUCxDTj1QdWJsaWMgS2V5IFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv" +
            "bmZpZ3VyYXRpb24sREM9dGFtZW15Y2VydHMtdGVzdHMsREM9bG9jYWw/Y2VydGlm" +
            "aWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1" +
            "dGlvblBvaW50hjdodHRwOi8vcGtpLnRhbWVteWNlcnRzLXRlc3RzLmxvY2FsL0Nl" +
            "cnREYXRhL1RFU1QtQ0EuY3Js";

        var cdpExt = new X509CertificateExtensionCrlDistributionPoint();

        cdpExt.AddUniformResourceIdentifier(
            "ldap:///CN=TEST-CA,CN=TEST-SERVER,CN=CDP,CN=Public Key Services," +
            "CN=Services,CN=Configuration,DC=tamemycerts-tests,DC=local" +
            "?certificateRevocationList?base?objectClass=cRLDistributionPoint"
        );
        cdpExt.AddUniformResourceIdentifier("http://pki.tamemycerts-tests.local/CertData/TEST-CA.crl");

        cdpExt.InitializeEncode();

        output.WriteLine(Convert.ToBase64String(cdpExt.RawData));

        Assert.Equal(expectedResult, Convert.ToBase64String(cdpExt.RawData));
    }

    [Fact]
    public void Building_short()
    {
        const string expectedResult =
            "MD8wPaA7oDmGN2h0dHA6Ly9wa2kudGFtZW15Y2VydHMtdGVzdHMubG9jYWwvQ2Vy" +
            "dERhdGEvVEVTVC1DQS5jcmw=";

        var cdpExt = new X509CertificateExtensionCrlDistributionPoint();

        cdpExt.AddUniformResourceIdentifier("http://pki.tamemycerts-tests.local/CertData/TEST-CA.crl");
        cdpExt.InitializeEncode();

        output.WriteLine(Convert.ToBase64String(cdpExt.RawData));

        Assert.Equal(expectedResult, Convert.ToBase64String(cdpExt.RawData));
    }
}