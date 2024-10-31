using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Principal;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;
using Xunit;

namespace TameMyCerts.Tests;

public class CertificateContentValidatorTests
{
    private readonly CertificateAuthorityConfiguration _caConfig;

    private readonly string _defaultCsr;

    private readonly ActiveDirectoryObject _dsObject;

    private readonly CertificateContentValidator _validator = new();


    public CertificateContentValidatorTests()
    {
        _caConfig = new CertificateAuthorityConfiguration(3, 1, "ADCS Labor Issuing CA 1",
            "ADCS Labor Issuing CA 1", "CA02", "pki.adcslabor.de", "CN=Configuration,DC=intra,DC=adcslabor,DC=de");

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

        _dsObject = new ActiveDirectoryObject(
            "CN=rudi,OU=Test-Users,DC=intra,DC=adcslabor,DC=de",
            0,
            new List<string> { "CN=PKI_UserCert,OU=ADCSLabor Gruppen,DC=intra,DC=adcslabor,DC=de" },
            new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase)
            {
                { "c", "DE" },
                { "company", "ADCS Labor" },
                { "displayName", "Rudi Ratlos" },
                { "department", "IT Operations" },
                { "givenName", "Rudi" },
                { "initials", "RR" },
                { "l", "München" },
                { "mail", "rudi@adcslabor.de" },
                { "name", "rudi" },
                { "sAMAccountName", "rudi" },
                { "sn", "Ratlos" },
                { "st", "Bavaria" },
                // Note that streetAddress is left out intentionally
                { "title", "General Manager" },
                { "userPrincipalName", "rudi@intra.adcslabor.de" },
                { "extensionAttribute1", "rudi1@intra.adcslabor.de" },
                { "extensionAttribute2", "rudi2@intra.adcslabor.de" }
            },
            new SecurityIdentifier("S-1-5-21-1381186052-4247692386-135928078-1225"),
            new List<string>()
        );
    }

    internal void PrintResult(CertificateRequestValidationResult result)
    {
        Console.WriteLine("0x{0:X} ({0}) {1}.", result.StatusCode,
            new Win32Exception(result.StatusCode).Message);
        Console.WriteLine(string.Join("\n", result.Description));

        if (result.CertificateExtensions.TryGetValue(WinCrypt.szOID_SUBJECT_ALT_NAME2, out var sanExt))
        {
            Console.WriteLine($@"SAN: {Convert.ToBase64String(sanExt)}");
        }

        if (result.CertificateExtensions.TryGetValue(WinCrypt.szOID_AUTHORITY_INFO_ACCESS, out var aisExt))
        {
            Console.WriteLine($@"AIA: {Convert.ToBase64String(aisExt)}");
        }

        if (result.CertificateExtensions.TryGetValue(WinCrypt.szOID_CRL_DIST_POINTS, out var cdpExt))
        {
            Console.WriteLine($@"CDP: {Convert.ToBase64String(cdpExt)}");
        }

        foreach (var item in result.CertificateProperties)
        {
            Console.WriteLine($"{item.Key} -> {item.Value}");
        }
    }

    [Fact]
    public void Does_add_valid_CDP_and_AIA()
    {
        const string expectedCdp =
            "MIIBKDCCASSgggEgoIIBHIaB0GxkYXA6Ly8vQ049QURDUyUyMExhYm9yJTIwSXNz" +
            "dWluZyUyMENBJTIwMSgxKSxDTj1DQTAyLENOPWNkcCxDTj1QdWJsaWMlMjBLZXkl" +
            "MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWludHJh" +
            "LERDPWFkY3NsYWJvcixEQz1kZT9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jh" +
            "c2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGR2h0dHA6Ly9wa2ku" +
            "YWRjc2xhYm9yLmRlL0NlcnREYXRhL0FEQ1MlMjBMYWJvciUyMElzc3VpbmclMjBD" +
            "QSUyMDEoMSkuY3Js";

        const string expectedAia =
            "MIIBSzCByAYIKwYBBQUHMAKGgbtsZGFwOi8vL0NOPUFEQ1MlMjBMYWJvciUyMElz" +
            "c3VpbmclMjBDQSUyMDEsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz" +
            "LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aW50cmEsREM9YWRjc2xh" +
            "Ym9yLERDPWRlP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZp" +
            "Y2F0aW9uQXV0aG9yaXR5MFMGCCsGAQUFBzAChkdodHRwOi8vcGtpLmFkY3NsYWJv" +
            "ci5kZS9DZXJ0RGF0YS9BRENTJTIwTGFib3IlMjBJc3N1aW5nJTIwQ0ElMjAxKDMp" +
            "LmNydDApBggrBgEFBQcwAYYdaHR0cDovL29jc3AuYWRjc2xhYm9yLmRlL29jc3A=";

        var policy = new CertificateRequestPolicy
        {
            CrlDistributionPoints = new List<string>
            {
                "ldap:///CN=%7%8,CN=%2,CN=cdp,CN=Public Key Services,CN=Services,%6%10",
                "http://%1/CertData/%3%8%9.crl"
            },
            AuthorityInformationAccess = new List<string>
            {
                "ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11",
                "http://%1/CertData/%3%4.crt"
            },
            OnlineCertificateStatusProtocol = new List<string>
            {
                "http://ocsp.adcslabor.de/ocsp"
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.True(result.CertificateExtensions.ContainsKey(WinCrypt.szOID_CRL_DIST_POINTS) && Convert
            .ToBase64String(result.CertificateExtensions[WinCrypt.szOID_CRL_DIST_POINTS])
            .Equals(expectedCdp));

        Assert.True(result.CertificateExtensions.ContainsKey(WinCrypt.szOID_AUTHORITY_INFO_ACCESS) &&
                    Convert.ToBase64String(
                            result.CertificateExtensions[WinCrypt.szOID_AUTHORITY_INFO_ACCESS])
                        .Equals(expectedAia));
    }

    [Fact]
    public void Does_add_static_RDN_when_not_present()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.Organization,
                    Value = "ADCS Labor"
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.True(result.CertificateProperties.Any(x =>
            x.Key.Equals(RdnTypes.NameProperty[RdnTypes.Organization]) && x.Value.Equals("ADCS Labor")));
    }

    [Fact]
    public void Does_not_add_static_RDN_when_present_and_not_forced()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de,O=test
        var request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDfDCCAmQCAQAwLzENMAsGA1UEChMEdGVzdDEeMBwGA1UEAxMVaW50cmFuZXQu\n" +
            "YWRjc2xhYm9yLmRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzdcL\n" +
            "8CWtsAMLalYb8oouXu18ZML6fhRIQtU9dW2H7DOi92e6EN89aBnmqYKtK7Bn0+xa\n" +
            "hOUeq1ttw5fOGEFKYUZQUhsepslaSZ9ciwjrQUcbrLANDajucMeXPjKcVOFTqunm\n" +
            "pRq4V8wBWVfbicnMW4j5Z1buIwslBZckH0MkGaZ2DFAQiPWwcQtgLO5qWhFpL9gw\n" +
            "oBQAPtwV/7IrazUsm8kaNCKROUkcKl4FijAPDFOOxRKRGQVkugqVv2JWWQamW6nS\n" +
            "SotKWC08XI/CASqnaE8EI9ea+WYmgEe3lAcnGCyVlhxglQNO6J50xbyhjIDXYlmv\n" +
            "A2e5fvVn3qOko5X9YQIDAQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMjI2\n" +
            "MjEuMjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU\n" +
            "a+LbTQ/nXfnja6OIwhofyAkJxnwwPgYJKwYBBAGCNxUUMTEwLwIBBQwKTEFQVE9Q\n" +
            "LVVXRQwOTEFQVE9QLVVXRVx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcN\n" +
            "AgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUA\n" +
            "IABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJ\n" +
            "KoZIhvcNAQELBQADggEBAMiD9HhBVMe5O8y1LwpUCLBv4y8tqrqMYF/KG8gBkWzF\n" +
            "0NZo14rogohbMjbaKY0uhICtBpYXN7xDBaQU6TNe1iEed5w7XgyyVfuocRe3OA4q\n" +
            "vRkmiAyn944Md5a+9Eyr6QoxLmT+TXTWiPbaTpcE584Rjq9X6saq06iRa2utDSE+\n" +
            "+EY72UdBC4U6vVfK2CfmrLcXLOG9y/AjNx969V4mFOAjjjnFrNCSEh0WAksTKU5i\n" +
            "YZ8AZq1iFeGZLXfdRg1ogKfrdl76X/RHa19jj3/plbQqzI9mW99caUBohnsnfqjY\n" +
            "2x76/opwmnDSL+YQMATEqFxCi1jKOQ5KymYdnzT+lU4=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.Organization,
                    Value = "ADCS Labor"
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.CertificateProperties.Any(x =>
            x.Key.Equals(RdnTypes.NameProperty[RdnTypes.Organization]) && x.Value.Equals("ADCS Labor")));
    }

    [Fact]
    public void Does_add_static_RDN_when_present_and_forced()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de,O=test
        var request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDfDCCAmQCAQAwLzENMAsGA1UEChMEdGVzdDEeMBwGA1UEAxMVaW50cmFuZXQu\n" +
            "YWRjc2xhYm9yLmRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzdcL\n" +
            "8CWtsAMLalYb8oouXu18ZML6fhRIQtU9dW2H7DOi92e6EN89aBnmqYKtK7Bn0+xa\n" +
            "hOUeq1ttw5fOGEFKYUZQUhsepslaSZ9ciwjrQUcbrLANDajucMeXPjKcVOFTqunm\n" +
            "pRq4V8wBWVfbicnMW4j5Z1buIwslBZckH0MkGaZ2DFAQiPWwcQtgLO5qWhFpL9gw\n" +
            "oBQAPtwV/7IrazUsm8kaNCKROUkcKl4FijAPDFOOxRKRGQVkugqVv2JWWQamW6nS\n" +
            "SotKWC08XI/CASqnaE8EI9ea+WYmgEe3lAcnGCyVlhxglQNO6J50xbyhjIDXYlmv\n" +
            "A2e5fvVn3qOko5X9YQIDAQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMjI2\n" +
            "MjEuMjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU\n" +
            "a+LbTQ/nXfnja6OIwhofyAkJxnwwPgYJKwYBBAGCNxUUMTEwLwIBBQwKTEFQVE9Q\n" +
            "LVVXRQwOTEFQVE9QLVVXRVx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcN\n" +
            "AgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUA\n" +
            "IABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJ\n" +
            "KoZIhvcNAQELBQADggEBAMiD9HhBVMe5O8y1LwpUCLBv4y8tqrqMYF/KG8gBkWzF\n" +
            "0NZo14rogohbMjbaKY0uhICtBpYXN7xDBaQU6TNe1iEed5w7XgyyVfuocRe3OA4q\n" +
            "vRkmiAyn944Md5a+9Eyr6QoxLmT+TXTWiPbaTpcE584Rjq9X6saq06iRa2utDSE+\n" +
            "+EY72UdBC4U6vVfK2CfmrLcXLOG9y/AjNx969V4mFOAjjjnFrNCSEh0WAksTKU5i\n" +
            "YZ8AZq1iFeGZLXfdRg1ogKfrdl76X/RHa19jj3/plbQqzI9mW99caUBohnsnfqjY\n" +
            "2x76/opwmnDSL+YQMATEqFxCi1jKOQ5KymYdnzT+lU4=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.Organization,
                    Value = "ADCS Labor",
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.True(result.CertificateProperties.Any(x =>
            x.Key.Equals(RdnTypes.NameProperty[RdnTypes.Organization]) && x.Value.Equals("ADCS Labor")));
    }

    [Fact]
    public void Does_return_if_already_denied()
    {
        var policy = new CertificateRequestPolicy();


        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result.SetFailureStatus();
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.NTE_FAIL));
    }

    [Fact]
    public void Does_not_add_static_RDN_when_length_constraint_was_violated()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.Country,
                    Value = "ABCDE",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }


    [Fact]
    public void Does_add_static_RDN_when_length_constraint_was_not_violated()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.Country,
                    Value = "DE",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Does_transfer_RDN_to_RDN()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.Organization,
                    Value = "{sdn:commonName}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        Assert.True(result.CertificateProperties
            .Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.Organization]))
            .Any(x => x.Value.Equals("intranet.adcslabor.de")));
    }

    [Fact]
    public void Does_transfer_RDN_to_RDN_and_clears_original_RDN()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = string.Empty,
                    Mandatory = true,
                    Force = true
                },
                new()
                {
                    Field = RdnTypes.Organization,
                    Value = "{sdn:commonName}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        Assert.True(result.CertificateProperties.ContainsKey(RdnTypes.NameProperty[RdnTypes.CommonName]) &&
                    result.CertificateProperties[RdnTypes.NameProperty[RdnTypes.CommonName]]
                        .Equals(string.Empty));
        Assert.True(result.CertificateProperties.ContainsKey(RdnTypes.NameProperty[RdnTypes.Organization]) &&
                    result.CertificateProperties[RdnTypes.NameProperty[RdnTypes.Organization]]
                        .Equals("intranet.adcslabor.de"));
    }

    [Fact]
    public void Does_transfer_RDN_to_SAN()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.DnsName,
                    Value = "{sdn:commonName}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals("MBeCFWludHJhbmV0LmFkY3NsYWJvci5kZQ=="));
    }

    [Fact]
    public void Does_transfer_inline_RDN_to_RDN()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.Organization,
                    Value = "{sdn:commonName}",
                    Mandatory = true,
                    Force = true
                }
            },
            ReadSubjectFromRequest = true
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        Assert.True(result.CertificateProperties
            .Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.Organization]))
            .Any(x => x.Value.Equals("intranet.adcslabor.de")));
    }

    [Fact]
    public void Does_transfer_inline_custom_RDN_to_RDN()
    {
        // 2048 Bit RSA Key
        // OID.1.2.3.4=test
        var request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEXDCCAsQCAQAwDzENMAsGAyoDBBMEdGVzdDCCAaIwDQYJKoZIhvcNAQEBBQAD\n" +
            "ggGPADCCAYoCggGBANMRqGEu7paMQtZYX53I5OJpjHTUKku0oZmtmvC4vVVWRBFt\n" +
            "LRK5gsA+dT6jbc+0/85vUiijGH2YlqH88xhFXxmTwHYid4lxdLDHiAy4fTf9eBAy\n" +
            "XvppR+pL4e+gMej+SkzAxSPdfwrCofpL8b9D/A40ryUVZrIutv0ki2RpenzDngeh\n" +
            "ekltB+jjFTBt4uBinmqw7QjrLXWmKWUaZSoUYLfaWuMbbDclojAdlkhYI1nsjDig\n" +
            "P+f+hUjDBw8Q/Pru890Pnf3rWcaCS2sd3Kj9pADNZXZpG7rj8dO8MF2MYM9V1lKy\n" +
            "IMgT9vbkwOYutyL0iFfob36S0Jc8OpoEqScESMkJOTFKi3YE5aZ3d8STjMSBj+ZL\n" +
            "EbUB1V6m++Mv9ARXaPWR5fZo+Cg+h4KZbW0Vax15+OGrdsV9TKfHJ7hEQ/a5zrck\n" +
            "6fCmrgRhLvctvuhImD/r9qupQgGn8MZr16WWE/tPcJzdct/CDUaPbDmLz1sHLLP3\n" +
            "Zn5ZwpR/xXcxQLYSHQIDAQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMjI2\n" +
            "MjEuMjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU\n" +
            "9laMO4ZZNH9fkro5WwwxOsUvE98wPgYJKwYBBAGCNxUUMTEwLwIBBQwKTEFQVE9Q\n" +
            "LVVXRQwOTEFQVE9QLVVXRVx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcN\n" +
            "AgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUA\n" +
            "IABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJ\n" +
            "KoZIhvcNAQELBQADggGBALIb2IrwNUnagED9Zk1TTJFsN9149PdPRyibTmgI8cU4\n" +
            "RLLVDG1lQH3XmI5sceQyAuWJdT7WE3gzvsXng9jrkyPLYjC/AHGfrrE6T1369+hc\n" +
            "Aj8Up9IlRSOYZJTgKyhUO2qooXzNx/E0OgzS7Oy3ihorxeyi7tx1USAy/zey04fe\n" +
            "pO7Bqcr2I0bWWevdleF8hO0BshRVAJqtBk5/ndLw4d0pfnBhRxCFpcfYVyn1ncL4\n" +
            "HzI/VgaHCo6h2KRulRuw/TjUC9FAk1xtp4Uwu0FwwaXJw1uQzR925A47TaBYiWmj\n" +
            "M1z3q3npwErfLexafSaQSnFKpiNfB74bmiC97jRPUATJ6jlJBqUG6wSmQ02iiUnW\n" +
            "+Yumqevz5yq7vdFB55LsDtOxb5/kEXjU6lzDISi805jWeZ0lgTCgrgbSRcbSl61t\n" +
            "qL9VH4nl+bfutTrzcXrhTO0gkc7o5AGGVO4+QQnNY1TYv+Tob1fQTdntzsYvcEPb\n" +
            "EM07b9QGN55RrrD4043BzA==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = "{sdn:OID.1.2.3.4}",
                    Mandatory = true,
                    Force = true
                }
            },
            ReadSubjectFromRequest = true
        };

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        Assert.True(result.CertificateProperties
            .Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.CommonName]))
            .Any(x => x.Value.Equals("test")));
    }

    [Fact]
    public void Does_transfer_inline_RDN_to_SAN()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.DnsName,
                    Value = "{sdn:commonName}",
                    Mandatory = true,
                    Force = true
                }
            },
            ReadSubjectFromRequest = true
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals("MBeCFWludHJhbmV0LmFkY3NsYWJvci5kZQ=="));
    }

    [Fact]
    public void Does_transfer_SAN_to_RDN()
    {
        // 2048 Bit RSA Key
        // dNSName=intranet.adcslabor.de,O=test
        var request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDcjCCAloCAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKD\n" +
            "ApNLGIPaChi+hKKhXS37BIexHpe2EqUg0PBWWz645ipCU6lJ8bR/fw0XQDj7xOHm\n" +
            "MGZ5R5olzvMUuA1ra9ZJfTqej8HCU1ShdUFaEfHbr4jEBNJZ7HM9lvJk7CbES/+T\n" +
            "iwbfotMqV94ulxj8CU2xbbb4a1VxezYubq5sXgyjs5iXNlwsoHU3S8sZAxB+vj4z\n" +
            "u0wZfx31J+RlFOwIVqbT9TywKsUU/Zn3SroxtNBrAPr15XuhMP3pUhC2I7SDg1IA\n" +
            "aBcJ5XvWhcppfP2/t5lI+14Q01Kzcj/Z2Lf0qf75jWOOYj4LJwnYAy8IujMRqq+k\n" +
            "qG2o1ZwSLamhgtlwXvECAwEAAaCCASswHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjIy\n" +
            "NjIxLjIwPgYJKwYBBAGCNxUUMTEwLwIBBQwKTEFQVE9QLVVXRQwOTEFQVE9QLVVX\n" +
            "RVx1d2UMDnBvd2Vyc2hlbGwuZXhlMGMGCSqGSIb3DQEJDjFWMFQwDgYDVR0PAQH/\n" +
            "BAQDAgeAMCMGA1UdEQEB/wQZMBeCFWludHJhbmV0LmFkY3NsYWJvci5kZTAdBgNV\n" +
            "HQ4EFgQUJXo02DrHw9nJgUFpfBYE5F7gh2UwZgYKKwYBBAGCNw0CAjFYMFYCAQAe\n" +
            "TgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBhAHIAZQAgAEsAZQB5ACAA\n" +
            "UwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcgMBADANBgkqhkiG9w0BAQsF\n" +
            "AAOCAQEAPae4VgzhPVLd8QDYgb6YzkzGOPplk08iVQKAnIj3wmrdfvAmP1HVLkAi\n" +
            "Qe1rhgAqUfB6Cbt4OtOG99ErXiBilLU2tMQkRtrNmg5eBNxTRGPDcRy2Q0qKOIfL\n" +
            "zGSH3ntOltDUOpfLYqUdy/JzyQGCkqoBPnRkOgAja9vmDPs4immkxbR1eFs2eqr4\n" +
            "hvivK93+rp3nUCegQxc66KaVVFcrz5nxluO1ol20mtsr9J5aQjXv2sJLRMC82qHl\n" +
            "/BaK8ZIqe9QmBkCUpvwRLXbH3+VyQa1lW4SITKMV3QFEgA+dZHwRc6bSn9ZM7GEc\n" +
            "APsCgCxhQ50QQZYSiG64N7urS+WVVA==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = "{san:dNSName}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        Assert.True(result.CertificateProperties
            .Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.CommonName]))
            .Any(x => x.Value.Equals("intranet.adcslabor.de")));
    }

    [Fact]
    public void Does_not_add_static_RDN_when_field_is_invalid()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = "this-is-invalid",
                    Value = "ADCS Labor",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Does_add_static_SAN_when_not_present()
    {
        const string expectedResult = "MByCGnRlc3QuaW50cmFuZXQuYWRjc2xhYm9yLmRl";

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.DnsName,
                    Value = "test.intranet.adcslabor.de"
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals(expectedResult));
    }

    [Fact]
    public void Does_add_more_than_one_static_SAN_when_differing_values_and_forced()
    {
        const string expectedResult =
            "MFaCGnRlc3QuaW50cmFuZXQuYWRjc2xhYm9yLmRlght0ZXN0Mi5pbnRyYW5ldC5hZGNzbGFib3IuZGWCG3Rlc3QzLmludHJhbmV0LmFkY3NsYWJvci5kZQ==";

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.DnsName,
                    Value = "test.intranet.adcslabor.de",
                    Force = true
                },
                new()
                {
                    Field = SanTypes.DnsName,
                    Value = "test2.intranet.adcslabor.de",
                    Force = true
                },
                new()
                {
                    Field = SanTypes.DnsName,
                    Value = "test3.intranet.adcslabor.de",
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals(expectedResult));
    }

    [Fact]
    public void Does_not_add_more_than_one_static_SAN_when_same_value_and_force()
    {
        const string expectedResult = "MByCGnRlc3QuaW50cmFuZXQuYWRjc2xhYm9yLmRl";

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.DnsName,
                    Value = "test.intranet.adcslabor.de",
                    Force = true
                },
                new()
                {
                    Field = SanTypes.DnsName,
                    Value = "test.intranet.adcslabor.de",
                    Force = true
                },
                new()
                {
                    Field = SanTypes.DnsName,
                    Value = "test.intranet.adcslabor.de",
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals(expectedResult));
    }

    [Fact]
    public void Does_not_add_static_SAN_when_present_and_not_forced()
    {
        const string expectedResult = "MByCGnRlc3QuaW50cmFuZXQuYWRjc2xhYm9yLmRl";

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.DnsName,
                    Value = "anothertest.intranet.adcslabor.de"
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result.SubjectAlternativeNameExtension.AddAlternativeName(SanTypes.DnsName, "test.intranet.adcslabor.de");
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals(expectedResult));
    }

    [Fact]
    public void Does_add_static_SAN_when_present_and_forced()
    {
        const string expectedResult =
            "MD+CIWFub3RoZXJ0ZXN0LmludHJhbmV0LmFkY3NsYWJvci5kZYIadGVzdC5pbnRyYW5ldC5hZGNzbGFib3IuZGU=";

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.DnsName,
                    Value = "test.intranet.adcslabor.de",
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result.SubjectAlternativeNameExtension.AddAlternativeName(SanTypes.DnsName,
            "anothertest.intranet.adcslabor.de");
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals(expectedResult));
    }


    [Fact]
    public void Does_not_add_static_SAN_when_field_is_ivalid()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = "this-is-invalid",
                    Value = "ADCS Labor",
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2));
    }

    [Fact]
    public void Does_not_add_static_SAN_when_field_is_incompatible()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.IpAddress,
                    Value = "ADCS Labor",
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2));
    }

    [Fact]
    public void Allow_and_add_one_RDN()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = "{ad:userPrincipalName}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.CertificateProperties
            .Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.CommonName]))
            .Any(x => x.Value.Equals("rudi@intra.adcslabor.de"))
        );
    }

    [Fact]
    public void Allow_and_add_one_RDN_CI()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = "{ad:userprincipalnAme}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.CertificateProperties
            .Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.CommonName]))
            .Any(x => x.Value.Equals("rudi@intra.adcslabor.de"))
        );
    }

    [Fact]
    public void Does_recognize_and_deny_valid_name_for_unknown_attribute()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = "{ad:test-attribute}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
        Assert.True(string.Join("\n", result.Description.ToList()).Contains("test-attribute"));
    }

    [Fact]
    public void Does_not_recognize_and_allow_invalid_name_for_unknown_attribute()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = "{ad:test?attribute}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Allow_and_add_one_combined_RDN()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = "{ad:sn}, {ad:givenName}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.CertificateProperties
            .Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.CommonName]))
            .Any(x => x.Value.Equals("Ratlos, Rudi"))
        );
    }

    [Fact]
    public void Allow_and_add_one_combined_RDN_with_twice_the_same_value()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = "{ad:givenName} is {ad:givenName}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.CertificateProperties
            .Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.CommonName]))
            .Any(x => x.Value.Equals("Rudi is Rudi"))
        );
    }

    [Fact]
    public void Allow_and_do_not_add_multiple_RDN()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = "{ad:userPrincipalName}",
                    Mandatory = true,
                    Force = true
                },
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = "{ad:userPrincipalName}",
                    Mandatory = true,
                    Force = true
                },
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = "{ad:userPrincipalName}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.CertificateProperties
                .Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.CommonName]))
                .Count(x => x.Value.Equals("rudi@intra.adcslabor.de")) == 1
        );
    }


    [Fact]
    public void Deny_if_unable_to_add_nonpresent_mandatory_DS_attribute()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.StreetAddress,
                    Value = "{ad:streetAddress}",
                    Mandatory = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
    }


    [Fact]
    public void Deny_if_mandatory_DS_attribute_too_long()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.Country,
                    Value = "{ad:c}",
                    Mandatory = true
                }
            }
        };


        var dsObject = _dsObject;

        dsObject.Attributes["c"] = "test";

        result = _validator.VerifyRequest(result, policy, dbRow, dsObject, _caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
    }


    [Fact]
    public void Deny_if_mandatory_DS_attribute_unknown()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = "test",
                    Value = "{ad:c}",
                    Mandatory = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
    }


    [Fact]
    public void Allow_but_dont_add_RDN_if_DS_attribute_unknown()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = "test",
                    Value = "{ad:c}"
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
    }


    [Fact]
    public void Allow_but_dont_add_RDN_if_DS_attribute_too_long()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.Country,
                    Value = "{ad:c}"
                }
            }
        };

        var dsObject = _dsObject;

        dsObject.Attributes["c"] = "test";

        result = _validator.VerifyRequest(result, policy, dbRow, dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.False(result.CertificateProperties.ContainsKey(RdnTypes.NameProperty[RdnTypes.Country]));
    }

    [Fact]
    public void Does_clear_existing_RDN()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = string.Empty,
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        Assert.True(result.CertificateProperties.ContainsKey(RdnTypes.NameProperty[RdnTypes.CommonName]) &&
                    result.CertificateProperties[RdnTypes.NameProperty[RdnTypes.CommonName]]
                        .Equals(string.Empty));
    }

    [Fact]
    public void Does_clear_nonexisting_RDN()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.State,
                    Value = string.Empty,
                    Force = true
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        Assert.True(result.CertificateProperties.ContainsKey(RdnTypes.NameProperty[RdnTypes.State]) &&
                    result.CertificateProperties[RdnTypes.NameProperty[RdnTypes.State]].Equals(string.Empty));
    }

    [Fact]
    public void Does_not_clear_existing_RDN_if_not_mandatory()
    {
        var policy = new CertificateRequestPolicy
        {
            OutboundSubject = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Value = string.Empty,
                    Force = false
                }
            }
        };

        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, null, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
        Assert.False(result.CertificateProperties.ContainsKey(RdnTypes.NameProperty[RdnTypes.CommonName]));
    }

    [Fact]
    public void Adds_one_San_from_DS()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.UserPrincipalName,
                    Value = "{ad:userPrincipalName}",
                    Mandatory = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.SubjectAlternativeNameExtension.ContainsAlternativeName(SanTypes.UserPrincipalName,
            _dsObject.Attributes["userPrincipalName"]));
    }


    [Fact]
    public void Adds_more_than_one_San_from_DS_if_differing_values()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.UserPrincipalName,
                    Value = "{ad:userPrincipalName}",
                    Mandatory = true,
                    Force = true
                },
                new()
                {
                    Field = SanTypes.UserPrincipalName,
                    Value = "{ad:extensionAttribute1}",
                    Mandatory = true,
                    Force = true
                },
                new()
                {
                    Field = SanTypes.UserPrincipalName,
                    Value = "{ad:extensionAttribute2}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.SubjectAlternativeNameExtension.AlternativeNames
            .Count(x => x.Key.Equals(SanTypes.UserPrincipalName)).Equals(3));
    }

    [Fact]
    public void Does_not_add_more_than_one_San_from_DS_if_same_value()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.UserPrincipalName,
                    Value = "{ad:userPrincipalName}",
                    Mandatory = true,
                    Force = true
                },
                new()
                {
                    Field = SanTypes.UserPrincipalName,
                    Value = "{ad:userPrincipalName}",
                    Mandatory = true,
                    Force = true
                },
                new()
                {
                    Field = SanTypes.UserPrincipalName,
                    Value = "{ad:userPrincipalName}",
                    Mandatory = true,
                    Force = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.SubjectAlternativeNameExtension.AlternativeNames
            .Count(x => x.Key.Equals(SanTypes.UserPrincipalName)).Equals(1));
    }

    [Fact]
    public void Deny_SAN_from_DS_if_incompatible_field_and_mandatory()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.IpAddress,
                    Value = "{ad:userPrincipalName}",
                    Mandatory = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.False(result.SubjectAlternativeNameExtension.ContainsAlternativeName(SanTypes.IpAddress,
            _dsObject.Attributes["userPrincipalName"]));
    }


    [Fact]
    public void Deny_SAN_from_DS_if_invalid_field_and_mandatory()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = "thisisinvalid",
                    Value = "{ad:userPrincipalName}",
                    Mandatory = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.False(result.SubjectAlternativeNameExtension.ContainsAlternativeName("thisisinvalid",
            _dsObject.Attributes["userPrincipalName"]));
    }


    [Fact]
    public void Deny_SAN_from_DS_if_invalid_attribute_and_mandatory()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.UserPrincipalName,
                    Value = "{ad:thisisinvalid}",
                    Mandatory = true
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.False(
            result.SubjectAlternativeNameExtension.ContainsAlternativeName(SanTypes.UserPrincipalName,
                "thisisinvalid"));
    }

    [Fact]
    public void Allow_SAN_from_DS_if_incompatible_field_and_not_mandatory()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.IpAddress,
                    Value = "{ad:userPrincipalName}",
                    Mandatory = false
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.SubjectAlternativeNameExtension.AlternativeNames
            .Count(x => x.Key.Equals(SanTypes.UserPrincipalName)).Equals(0));
    }


    [Fact]
    public void Allow_SAN_from_DS_if_invalid_field_and_not_mandatory()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = "thisisinvalid",
                    Value = "{ad:userPrincipalName}",
                    Mandatory = false
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.SubjectAlternativeNameExtension.AlternativeNames
            .Count(x => x.Key.Equals(SanTypes.UserPrincipalName)).Equals(0));
    }


    [Fact]
    public void Allow_SAN_from_DS_if_invalid_attribute_and_not_mandatory()
    {
        var dbRow = new CertificateDatabaseRow(_defaultCsr, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy
        {
            OutboundSubjectAlternativeName = new List<OutboundSubjectRule>
            {
                new()
                {
                    Field = SanTypes.UserPrincipalName,
                    Value = "{ad:thisisinvalid}",
                    Mandatory = false
                }
            }
        };

        result = _validator.VerifyRequest(result, policy, dbRow, _dsObject, _caConfig);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.SubjectAlternativeNameExtension.AlternativeNames
            .Count(x => x.Key.Equals(SanTypes.UserPrincipalName)).Equals(0));
    }
}