using FluentAssertions;
using Microsoft.VisualStudio.TestPlatform.Utilities;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;
using Xunit;
using Xunit.Abstractions;
using static System.Net.Mime.MediaTypeNames;

namespace TameMyCerts.Tests;

public class XMLPolicyTests
{
    private ETWLoggerListener _listener;
    private readonly ITestOutputHelper output;

    public XMLPolicyTests(ITestOutputHelper output)
    {
        this.output = output;
        this._listener = new ETWLoggerListener();
    }

    internal void PrintResult(CertificateRequestValidationResult result)
    {
        output.WriteLine("0x{0:X} ({0}) {1}.", result.StatusCode,
            new Win32Exception(result.StatusCode).Message);
        output.WriteLine(string.Join("\n", result.Description));
    }

    [Fact]
    public void Test_reading_compliant_XML()
    {
        var filename = Path.GetTempFileName();

        string sampleXML = @"<CertificateRequestPolicy xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
  xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <AuditOnly>false</AuditOnly>
</CertificateRequestPolicy>";
        File.WriteAllText(filename, sampleXML);

        CertificateRequestPolicyCacheEntry cacheEntry = new CertificateRequestPolicyCacheEntry(filename);

        Assert.False(cacheEntry.CertificateRequestPolicy.AuditOnly);
        Assert.Empty(cacheEntry.ErrorMessage);

        File.Delete(filename);
    }

    [Fact]
    public void Test_Unknown_XML_Element()
    {
        var filename = Path.GetTempFileName();

        string sampleXML = @"<CertificateRequestPolicy xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
  xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <ThisDoewNotExist>false</ThisDoewNotExist>
</CertificateRequestPolicy>
";
        File.WriteAllText(filename, sampleXML);
        _listener.ClearEvents();

        CertificateRequestPolicyCacheEntry cacheEntry = new CertificateRequestPolicyCacheEntry(filename);

        Assert.Empty(cacheEntry.ErrorMessage);
        Assert.Equal(2, _listener.Events.Count);
        Assert.Equal(92, _listener.Events[0].EventId);
        output.WriteLine(_listener.Events[0].Message);
        File.Delete(filename);
    }

    [Fact]
    public void Test_Unknown_XML_Element2()
    {
        var filename = Path.GetTempFileName();

        string sampleXML = @"<CertificateRequestPolicy xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
  xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <DirectoryServicesMapping><AllowedOrganizationalUnits><Test>This should fault</Test></AllowedOrganizationalUnits></DirectoryServicesMapping>
</CertificateRequestPolicy>
";
        File.WriteAllText(filename, sampleXML);
        _listener.ClearEvents();

        CertificateRequestPolicyCacheEntry cacheEntry = new CertificateRequestPolicyCacheEntry(filename);

        Assert.Empty(cacheEntry.ErrorMessage);
        Assert.Equal(2, _listener.Events.Count);
        Assert.Equal(92, _listener.Events[0].EventId);

        File.Delete(filename);
    }

    [Fact]
    public void Test_Yubikey_Policies()
    {
        var filename = Path.GetTempFileName();

        string sampleXML = @"<CertificateRequestPolicy xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
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

        CertificateRequestPolicyCacheEntry cacheEntry = new CertificateRequestPolicyCacheEntry(filename);

        //Assert.Empty(cacheEntry.ErrorMessage);
        //Assert.Equal(2, _listener.Events.Count);
        Assert.DoesNotContain(92, _listener.Events.Select(e => e.EventId));
        File.Delete(filename);
    }


    [Fact]
    public void Broken_XML_Policies()
    {
        var filename = Path.GetTempFileName();

        string sampleXML = @"<CertificateRequestPolicy xmlns:xsi=""""http://www.w3.org/2001/XMLSchema-instance""""
  xmlns:xsd=""""http://www.w3.org/2001/XMLSchema"""">
</CertificateRequestPolicy>
";
        File.WriteAllText(filename, sampleXML);
        _listener.ClearEvents();

        CertificateRequestPolicyCacheEntry cacheEntry = new CertificateRequestPolicyCacheEntry(filename);

        output.WriteLine(cacheEntry.ErrorMessage);
        Assert.Contains(94, _listener.Events.Select(e => e.EventId));
        File.Delete(filename);
    }

}