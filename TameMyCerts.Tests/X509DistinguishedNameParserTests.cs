using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using TameMyCerts.Models;
using TameMyCerts.X509;
using Xunit;

namespace TameMyCerts.Tests;

public sealed class X509DistinguishedNameParserTests
{
    /*
     * serialNumber = "serialNumber"
     * unstructuredAddress = "unstructuredAddress"
     * unstructuredName = "unstructuredName"
     * streetAddress = "streetAddress"
     * surname = "surname"
     * initials = "ABC"
     * givenName = "givenName"
     * title = "title"
     * countryName = "DE"
     * domainComponent = "domainComponent"
     * stateOrProvinceName = "stateOrProvinceName"
     * localityName = "localityName"
     * organizationName = "organizationName"
     * organizationalUnitName = "organizationalUnitName"
     * commonName = "commonName"
     * emailAddress = "emailAddress"
     */
    private static readonly byte[] SampleSubjectDn = Convert.FromBase64String(
        "MIIBiTEVMBMGA1UEBRMMc2VyaWFsTnVtYmVyMSIwIAYJKoZIhvcNAQkIDBN1bnN0" +
        "cnVjdHVyZWRBZGRyZXNzMR8wHQYJKoZIhvcNAQkCDBB1bnN0cnVjdHVyZWROYW1l" +
        "MRYwFAYDVQQJDA1zdHJlZXRBZGRyZXNzMRAwDgYDVQQEDAdzdXJuYW1lMQwwCgYD" +
        "VQQrDANBQkMxEjAQBgNVBCoMCWdpdmVuTmFtZTEOMAwGA1UEDAwFdGl0bGUxCzAJ" +
        "BgNVBAYTAkRFMR8wHQYKCZImiZPyLGQBGRYPZG9tYWluQ29tcG9uZW50MRwwGgYD" +
        "VQQIDBNzdGF0ZU9yUHJvdmluY2VOYW1lMRUwEwYDVQQHDAxsb2NhbGl0eU5hbWUx" +
        "GTAXBgNVBAoMEG9yZ2FuaXphdGlvbk5hbWUxHzAdBgNVBAsMFm9yZ2FuaXphdGlv" +
        "bmFsVW5pdE5hbWUxEzARBgNVBAMMCmNvbW1vbk5hbWUxGzAZBgkqhkiG9w0BCQEW" +
        "DGVtYWlsQWRkcmVzcw=="
    );

    [Fact]
    public void Parse_ValidSubjectDn_ReturnsExpectedAttributes()
    {
        var attributes = X509DistinguishedNameParser.Parse(SampleSubjectDn);

        Assert.IsType<List<KeyValuePair<string, string>>>(attributes);
        Assert.Equal(16, attributes.Count);
        Assert.NotNull(attributes);
        Assert.NotEmpty(attributes);
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.CommonName, Value: "commonName" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.Country, Value: "DE" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.Organization, Value: "organizationName" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.OrgUnit, Value: "organizationalUnitName" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.Locality, Value: "localityName" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.State, Value: "stateOrProvinceName" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.SurName, Value: "surname" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.GivenName, Value: "givenName" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.Email, Value: "emailAddress" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.DeviceSerialNumber, Value: "serialNumber" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.UnstructuredAddress, Value: "unstructuredAddress" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.UnstructuredName, Value: "unstructuredName" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.StreetAddress, Value: "streetAddress" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.Initials, Value: "ABC" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.Title, Value: "title" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.DomainComponent, Value: "domainComponent" });
    }

    [Fact]
    public void Parse_ValidSubjectDn_ReturnsExpectedAttributes_UnknownRdn()
    {
        var sampleSubjectDn = Convert.FromBase64String(
            "MDUxDTALBgMqAwQTBHRlc3QxJDAiBgNVBAMTG3d3dy5pbnRyYS50bWN0ZXN0cy5p" +
            "bnRlcm5hbA=="
        );

        var attributes = X509DistinguishedNameParser.Parse(sampleSubjectDn);

        Assert.IsType<List<KeyValuePair<string, string>>>(attributes);
        Assert.NotNull(attributes);
        Assert.NotEmpty(attributes);
        Assert.Contains(attributes, kv => kv is { Key: "OID.1.2.3.4", Value: "test" });
    }

    [Fact]
    public void Parse_ValidSubjectDn_ReturnsExpectedAttributes_Multiple()
    {
        /*
         * commonName = first
         * commonName = second
        ** commonName = third 
         */
        var sampleSubjectDn = Convert.FromBase64String(
            "MDExDjAMBgNVBAMTBXRoaXJkMQ8wDQYDVQQDEwZzZWNvbmQxDjAMBgNVBAMTBWZp" +
            "cnN0"
        );

        var attributes = X509DistinguishedNameParser.Parse(sampleSubjectDn);

        Assert.IsType<List<KeyValuePair<string, string>>>(attributes);
        Assert.Equal(3, attributes.Count);
        Assert.NotNull(attributes);
        Assert.NotEmpty(attributes);
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.CommonName, Value: "first" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.CommonName, Value: "second" });
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.CommonName, Value: "third" });
    }

    [Fact]
    public void Parse_ValidSubjectDn_ReturnsExpectedAttributes_Empty_Sequence()
    {
        var sampleSubjectDn = Array.Empty<byte>();

        var attributes = X509DistinguishedNameParser.Parse(sampleSubjectDn);

        Assert.IsType<List<KeyValuePair<string, string>>>(attributes);
        Assert.NotNull(attributes);
        Assert.Empty(attributes);
    }

    [Fact]
    public void Parse_RandomGarbage_ThrowsAsnContentException()
    {
        var garbage = RandomNumberGenerator.GetBytes(64);

        Assert.Throws<AsnContentException>(() =>
            X509DistinguishedNameParser.Parse(garbage));
    }

    [Fact]
    public void Parse_ValidAsn1ButWrongStructure_ThrowsAsnContentException()
    {
        // SEQUENCE { INTEGER 5 }
        byte[] wrongStructure =
        [
            0x30, 0x03,
            0x02, 0x01, 0x05
        ];

        Assert.Throws<AsnContentException>(() =>
            X509DistinguishedNameParser.Parse(wrongStructure));
    }

    [Fact]
    public void Parse_TrailingGarbageAfterValidDn_ThrowsAsnContentException()
    {
        var trailingGarbage = new byte[SampleSubjectDn.Length + 3];
        Buffer.BlockCopy(SampleSubjectDn, 0, trailingGarbage, 0, SampleSubjectDn.Length);

        // Append junk
        trailingGarbage[^3] = 0xFF;
        trailingGarbage[^2] = 0xEE;
        trailingGarbage[^1] = 0xDD;

        Assert.Throws<AsnContentException>(() =>
            X509DistinguishedNameParser.Parse(trailingGarbage));
    }

    [Fact]
    public void Parse_NonStringAttributeValue_UsesHexFallback()
    {
        // Name ::= SEQUENCE
        //   RDN ::= SET
        //     ATV ::= SEQUENCE
        //       OID 2.5.4.3 (CN)
        //       OCTET STRING { 0x01, 0x02, 0x03 }
        byte[] unsupportedButValidValueType =
        [
            0x30, 0x0E, // SEQUENCE
            0x31, 0x0C, // SET
            0x30, 0x0A, // SEQUENCE
            0x06, 0x03, 0x55, 0x04, 0x03, // OID 2.5.4.3 (CN)
            0x04, 0x03, 0x01, 0x02, 0x03 // OCTET STRING
        ];

        var attributes = X509DistinguishedNameParser.Parse(unsupportedButValidValueType);

        Assert.Single(attributes);

        // hex fallback
        Assert.Contains(attributes, kv => kv is { Key: RdnTypes.CommonName, Value: "0403010203" });
    }
}