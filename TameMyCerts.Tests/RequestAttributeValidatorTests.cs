using Microsoft.VisualStudio.TestPlatform.ObjectModel.Client;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;
using Xunit;
using Xunit.Abstractions;

namespace TameMyCerts.Tests;

public class RequestAttributeValidatorTests
{
    private const string DATETIME_RFC2616 = "ddd, d MMM yyyy HH:mm:ss 'GMT'";

    private readonly string _defaultCsr;

    private readonly RequestAttributeValidator _validator = new();

    private readonly ITestOutputHelper _output;

    public RequestAttributeValidatorTests(ITestOutputHelper output)
    {
        this._output = output;
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        _defaultCsr =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDbTCCAlUCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApucZpFuF0+fvdL5C3jggO6vO\n" +
            "9PA39MnPG0VQBy1n2pdhD/WwIt3St6UuMTXyNzEqSqm396Dw6+1iLCcP4DioLywd\n" +
            "9rVHOAFmYNeahM24rYk9z+8rgx5a4GhtK6uSXD87aNDwz7l+QCnjapZu1bqfe/s+\n" +
            "Wzo3e/jiSNIUUiY6/DQnHcZpPn/nBruLih0muZFWCevIRwu/w05DMrX9KTKax06l\n" +
            "TJw+bQshKasiVDDW+0K5eDzvLu7cS6/Z9vVYHD7gGJNmX+YaJY+JS9tGaGyvDUiV\n" +
            "ww+Do5S8p13dXqY/xwMngkq3kkvTB8hstxE1pd07OQojZ1SaLFEyh3pX7abXMQID\n" +
            "AQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkqhkiG9w0B\n" +
            "CQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUsp05C4spRvndIOKWrM7O\n" +
            "aXVZLCUwPgYJKwYBBAGCNxUUMTEwLwIBBQwKb3R0aS1vdHRlbAwOT1RUSS1PVFRF\n" +
            "TFx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcNAgIxWDBWAgEAHk4ATQBp\n" +
            "AGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABv\n" +
            "AHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJKoZIhvcNAQELBQADggEB\n" +
            "ABCVBVb7DJjiDP5SbSpw08nvrwnx5kiQ21xR7AJmtSYPLmsmC7uIPxk8Jsq1hDUO\n" +
            "e2adcbMup6QY7GJGuc4OWhiaisKAeZB7Tcy5SEZIWe85DlkxEgLVFB9opmf+V3fA\n" +
            "d/ZtYS0J7MPg6F9UEra30T3CcHlH5Y8NlMtaZmqjfXyw2C5YkahEfSmk2WVaZiSf\n" +
            "8edZDjIw5eRZY/9QMi2JEcmSbq0DImiP4ou46aQ0U5iRGSNX+armMIhGJ1ycDXTM\n" +
            "SBDUN6qWGioX8NHTlUmebLijw3zSFMnIuYWhXF7FZ1IKMPySzVmquvBAjzT4kWSw\n" +
            "0bAr5OaOzHm7POogsgE8J1Y=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";
    }

    internal void PrintResult(CertificateRequestValidationResult result)
    {
        _output.WriteLine("0x{0:X} ({0}) {1}.", result.StatusCode,
            new Win32Exception(result.StatusCode).Message);
        _output.WriteLine(string.Join("\n", result.Description));
    }

    [Fact]
    public void Does_return_if_already_denied()
    {
        var startDate = DateTimeOffset.Now.AddDays(1);

        var caConfig = new CertificateAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTEENDDATE);

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string>
            {
                {
                    "StartDate",
                    startDate.ToString(DATETIME_RFC2616, CultureInfo.InvariantCulture.DateTimeFormat)
                }
            });

        var result = new CertificateRequestValidationResult(dbRow);

        result.SetFailureStatus();

        result = _validator.VerifyRequest(result, dbRow, caConfig);
        
        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.NTE_FAIL));
    }

    [Fact]
    public void Deny_StartDate_invalid()
    {
        var caConfig = new CertificateAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTEENDDATE);

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string> { { "StartDate", "not a valid datetime" } });

        var result = new CertificateRequestValidationResult(dbRow);


        result = _validator.VerifyRequest(result, dbRow, caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode == WinError.ERROR_INVALID_TIME);
    }

    [Fact]
    public void Allow_StartDate_no_flag()
    {
        var caConfig = new CertificateAuthorityConfiguration(0);

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string> { { "StartDate", "not a valid datetime" } });

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, dbRow, caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode == WinError.ERROR_SUCCESS);
    }

    [Fact]
    public void Deny_StartDate_in_the_past()
    {
        var caConfig = new CertificateAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTEENDDATE);

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string> { { "StartDate", "Wed, 19 Oct 2022 20:00:00 GMT" } });

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, dbRow, caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode == WinError.ERROR_INVALID_TIME);
    }

    [Fact]
    public void Deny_StartDate_after_NotAfter()
    {
        var caConfig = new CertificateAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTEENDDATE);

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string> { { "StartDate", "Thu, 31 Dec 2099 20:00:00 GMT" } });

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, dbRow, caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode == WinError.ERROR_INVALID_TIME);
    }

    [Fact]
    public void Allow_StartDate()
    {
        var startDate = DateTimeOffset.Now.AddDays(1);

        var caConfig = new CertificateAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTEENDDATE);

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string>
            {
                {
                    "StartDate",
                    startDate.ToString(DATETIME_RFC2616, CultureInfo.InvariantCulture.DateTimeFormat)
                }
            });

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, dbRow, caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode == WinError.ERROR_SUCCESS);

        // TODO: Compare actual value
    }

    [Fact]
    public void Deny_invalid_flags()
    {
        var caConfig = new CertificateAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2);

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string> { { "saN", "doesnt-matter" } });

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, dbRow, caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode == WinError.NTE_FAIL);
    }

    [Fact]
    public void Allow_valid_flags()
    {
        var caConfig = new CertificateAuthorityConfiguration(0);

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string> { { "saN", "doesnt-matter" } });

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, dbRow, caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode == WinError.ERROR_SUCCESS);
    }

    [Fact]
    public void Deny_invalid_flags_no_attribute()
    {
        var caConfig = new CertificateAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2);

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, dbRow, caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode == WinError.ERROR_SUCCESS);
    }
}