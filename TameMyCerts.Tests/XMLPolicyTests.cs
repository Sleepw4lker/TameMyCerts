using System.IO;
using System.Linq;
using TameMyCerts.Models;
using Xunit;
using Xunit.Abstractions;

namespace TameMyCerts.Tests;

public class XMLPolicyTests
{
    private readonly ETWLoggerListener _listener;
    private readonly ITestOutputHelper _output;

    public XMLPolicyTests(ITestOutputHelper output)
    {
        _output = output;
        _listener = new ETWLoggerListener();
    }

    [Fact]
    public void Test_reading_compliant_XML()
    {
        var filename = Path.GetTempFileName();

        var sampleXML = @"<CertificateRequestPolicy xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
  xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <AuditOnly>false</AuditOnly>
</CertificateRequestPolicy>";
        File.WriteAllText(filename, sampleXML);

        var cacheEntry = new CertificateRequestPolicyCacheEntry(filename);

        Assert.False(cacheEntry.CertificateRequestPolicy.AuditOnly);
        Assert.Empty(cacheEntry.ErrorMessage);

        File.Delete(filename);
    }

    [Fact]
    public void Test_Unknown_XML_Element()
    {
        var filename = Path.GetTempFileName();

        var sampleXML = @"<CertificateRequestPolicy xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
  xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <ThisDoewNotExist>false</ThisDoewNotExist>
</CertificateRequestPolicy>
";
        File.WriteAllText(filename, sampleXML);
        _listener.ClearEvents();

        var cacheEntry = new CertificateRequestPolicyCacheEntry(filename);

        Assert.NotEmpty(cacheEntry.ErrorMessage);
        Assert.Equal(2, _listener.Events.Count);
        Assert.Equal(92, _listener.Events[0].EventId);
        _output.WriteLine(_listener.Events[0].Message);
        File.Delete(filename);
    }

    [Fact]
    public void Test_Unknown_XML_Element2()
    {
        var filename = Path.GetTempFileName();

        var sampleXML = @"<CertificateRequestPolicy xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
  xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <DirectoryServicesMapping><AllowedOrganizationalUnits><Test>This should fault</Test></AllowedOrganizationalUnits></DirectoryServicesMapping>
</CertificateRequestPolicy>
";
        File.WriteAllText(filename, sampleXML);
        _listener.ClearEvents();

        var cacheEntry = new CertificateRequestPolicyCacheEntry(filename);

        Assert.NotEmpty(cacheEntry.ErrorMessage);
        Assert.Equal(2, _listener.Events.Count);
        Assert.Equal(92, _listener.Events[0].EventId);

        File.Delete(filename);
    }

    [Fact]
    public void Test_Yubikey_Policies()
    {
        var filename = Path.GetTempFileName();

        var sampleXML = @"<CertificateRequestPolicy xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
  xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
  <YubiKeyPolicies>
  <YubiKeyPolicy>
    <Action>Allow</Action>
      <Slot>
        <string>9A</string>
      </Slot>
  </YubiKeyPolicy>
  </YubiKeyPolicies>
</CertificateRequestPolicy>

";
        File.WriteAllText(filename, sampleXML);
        _listener.ClearEvents();

        var cacheEntry = new CertificateRequestPolicyCacheEntry(filename);

        //Assert.Empty(cacheEntry.ErrorMessage);
        //Assert.Equal(2, _listener.Events.Count);
        Assert.DoesNotContain(92, _listener.Events.Select(e => e.EventId));
        File.Delete(filename);
    }


    [Fact]
    public void Broken_XML_Policies()
    {
        var filename = Path.GetTempFileName();

        var sampleXML = @"<CertificateRequestPolicy xmlns:xsi=""""http://www.w3.org/2001/XMLSchema-instance""""
  xmlns:xsd=""""http://www.w3.org/2001/XMLSchema"""">
</CertificateRequestPolicy>
";
        File.WriteAllText(filename, sampleXML);
        _listener.ClearEvents();

        var cacheEntry = new CertificateRequestPolicyCacheEntry(filename);

        _output.WriteLine(cacheEntry.ErrorMessage);
        Assert.Contains(94, _listener.Events.Select(e => e.EventId));
        File.Delete(filename);
    }

    [Fact]
    public void Test_Broken_XML()
    {
        var filename = Path.GetTempFileName();
        File.Delete(filename);

        var sampleXML = @"<CertificateRequestPolicy xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
  xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <directoryservicesmapping><AllowedOrganizationalUnits><Test>This should fault</Test></AllowedOrganizationalUnits></directoryservicesmapping>
</CertificateRequestPolicy>
";
        File.WriteAllText($"{filename}.xml", sampleXML);
        _listener.ClearEvents();

        var cache = new CertificateRequestPolicyCache(Path.GetTempPath());
        var cacheEntry = cache.GetCertificateRequestPolicy(Path.GetFileName(filename));

        Assert.NotNull(cacheEntry);
        Assert.Null(cacheEntry.CertificateRequestPolicy);

        File.Delete($"{filename}.xml");
    }
}