using System;
using TameMyCerts.X509;
using Xunit;

namespace TameMyCerts.Tests;

public class X509CertificateExtensionTests
{
    [Theory]
    [InlineData("http://example.com/space here", "http://example.com/space%20here")]
    [InlineData("https://example.com/a b?c=d e", "https://example.com/a%20b?c=d%20e")]
    [InlineData("ldap://host/OU=Test Users,DC=example,DC=com", "ldap://host/OU=Test%20Users,DC=example,DC=com")]
    [InlineData("http://example.com/!$&'()*+,;=", "http://example.com/!$&'()*+,;=")] // reserved chars
    [InlineData("http://example.com/abc-_.~", "http://example.com/abc-_.~")] // unreserved chars
    [InlineData("http://example.com/���", "http://example.com/���")] // non-ASCII chars (should not be encoded by current logic)
    [InlineData("ftp://example.com/space here", "ftp://example.com/space here")] // unsupported scheme, no encoding
    [InlineData("notauri", "notauri")] // not a URI, no encoding
    public void EncodeUri_Rfc3986Compliance(string input, string expected)
    {
        var result = X509CertificateExtension.EncodeUri(input);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void EncodeUri_NullInput_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => X509CertificateExtension.EncodeUri(null));
    }
}