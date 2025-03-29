using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;
using Xunit;
using Xunit.Abstractions;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace TameMyCerts.Tests;

public class YubikeyValidatorTests
{
    private readonly CertificateAuthorityConfiguration _caConfig;
    private readonly CertificateContentValidator _ccValidator = new();

    private readonly ETWLoggerListener _listener;

    private readonly ITestOutputHelper _output;
    private readonly CertificateRequestPolicy _policy;
    private readonly YubikeyValidator _ykValidator;
    private readonly string _yubikey_valid_5_4_3_Always_Never_UsbAKeychain_9a_Normal_ECC_384_CSR;
    private readonly string _yubikey_valid_5_4_3_Once_Cached_UsbAKeychain_9a_FIPS_RSA_2048_CSR;
    private readonly CertificateDatabaseRow _yubikey_valid_5_4_3_Once_Cached_UsbAKeychain_9a_FIPS_RSA_2048_dbRow;
    private readonly string _yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR;
    private readonly CertificateDatabaseRow _yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_dbRow;
    private readonly string _yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR;
    private readonly CertificateDatabaseRow _yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_dbRow;

    private readonly X509Certificate2 _yubikeyPivRootCaSerial263751 = new(Convert.FromBase64String(
        "MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1" +
        "YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY" +
        "DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg" +
        "U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2" +
        "cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E" +
        "ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq" +
        "joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH" +
        "BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf" +
        "wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet" +
        "X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0" +
        "1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3" +
        "DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s" +
        "XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2" +
        "lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d" +
        "bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq" +
        "Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8" +
        "SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7"));


    public YubikeyValidatorTests(ITestOutputHelper output)
    {
        // Setup a fake CA configuration
        _caConfig = new CertificateAuthorityConfiguration(3, 1, "ADCS Labor Issuing CA 1",
            "ADCS Labor Issuing CA 1", "CA02", "pki.adcslabor.de", "CN=Configuration,DC=intra,DC=adcslabor,DC=de");

        // Sample CSR from a Yubikey with attestation included
        _yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIIItzCCB58CAQAwDzENMAsGA1UEAwwEdGFkYTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
            "ggEPADCCAQoCggEBAMNISyiNgES5Etvd834NoYVjJW4T4i8rEmjiynEWg3M0SrOv\n" +
            "nEEbDGDjtQO9+AYJTbsHthLeKZd7eiAbniKUZ3T7H76rPM/2x/al/tfsSNHsX+ln\n" +
            "/llojkekUYTs4PXBXt7uOoOv/eqEXVy9fI80kKOqI1zmCOrD/BoN4cKniWGM1ZNM\n" +
            "g6GR/318oigbA0wztMbio0ZYMT99cit/6iqaNvAzqfOqNFELcHsUzm1eu9pnjbtN\n" +
            "LNObiZ4CfACn2JDz6PXFSw5kU8esTSsCcK8F97FWOkL7sOvlrocS1XLzKJJlyP0w\n" +
            "zpzv4TY98OIhTRFDCcSIz7yAWWD7JRaGkTtjjsUCAwEAAaCCBmEwggZdBgkqhkiG\n" +
            "9w0BCQ4xggZOMIIGSjCCAzQGCisGAQQBgsQKAwsEggMkMIIDIDCCAgigAwIBAgIQ\n" +
            "AVFGpCH0S98dxkg8TI1/4zANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZZdWJp\n" +
            "Y28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAwMFoYDzIwNTIwNDE3MDAw\n" +
            "MDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRlc3RhdGlvbiA5YTCCASIw\n" +
            "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMNISyiNgES5Etvd834NoYVjJW4T\n" +
            "4i8rEmjiynEWg3M0SrOvnEEbDGDjtQO9+AYJTbsHthLeKZd7eiAbniKUZ3T7H76r\n" +
            "PM/2x/al/tfsSNHsX+ln/llojkekUYTs4PXBXt7uOoOv/eqEXVy9fI80kKOqI1zm\n" +
            "COrD/BoN4cKniWGM1ZNMg6GR/318oigbA0wztMbio0ZYMT99cit/6iqaNvAzqfOq\n" +
            "NFELcHsUzm1eu9pnjbtNLNObiZ4CfACn2JDz6PXFSw5kU8esTSsCcK8F97FWOkL7\n" +
            "sOvlrocS1XLzKJJlyP0wzpzv4TY98OIhTRFDCcSIz7yAWWD7JRaGkTtjjsUCAwEA\n" +
            "AaNOMEwwEQYKKwYBBAGCxAoDAwQDBQQDMBQGCisGAQQBgsQKAwcEBgIEASwDdzAQ\n" +
            "BgorBgEEAYLECgMIBAICATAPBgorBgEEAYLECgMJBAEBMA0GCSqGSIb3DQEBCwUA\n" +
            "A4IBAQCX/GpfqmFU6XeK80F8lpnz+d9ijl22/DtgIpsuqO8/JL+oNo1wOLtOQ7SU\n" +
            "J/VlwoviB6M9ZyctV2zjgXITnxZWZ9XRI3iD3qnonSOBQXviLFpeIelzoGchEOSd\n" +
            "fDpNGv6+D9/5xkkil40TlC3lMdtiDBSSN3RFJ1i7CXPPV7hAtDev/AA7hpW0Bnxs\n" +
            "tf5RNRh5QqRyaKvGDnVL7ukPIjwuTR0LPLvckw7Qm0NSw6z/kGTwo1ujhb3LhH0g\n" +
            "9BrKyMoObwpr/W0QjJmRjChIgi40pQ7D5Y/nksfSZi4CQyRgzmbAjrJWFZSPXs+B\n" +
            "y3cv7hY6DbeaiVG+bMNi53L728ULMIIDDgYKKwYBBAGCxAoDAgSCAv4wggL6MIIB\n" +
            "4qADAgECAgkA6MPdeZ5DO2IwDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgWXVi\n" +
            "aWNvIFBJViBSb290IENBIFNlcmlhbCAyNjM3NTEwIBcNMTYwMzE0MDAwMDAwWhgP\n" +
            "MjA1MjA0MTcwMDAwMDBaMCExHzAdBgNVBAMMFll1YmljbyBQSVYgQXR0ZXN0YXRp\n" +
            "b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9PT4n9BHqypwVUo2q\n" +
            "vOyQUG96nZZpArJfgc/tAs8/Ylk2brMQjHIi0B8faIRbjrSsOS6vVk6ZX+P/cX1t\n" +
            "R1a2hKZ+hbaUuC6wETPQWA5LzWm/PqFx/b6Zbwp6B29moNtEjY45d3e217QPjwlr\n" +
            "wPjHTmmPZ8xZh7x/lircGO+ezkC2VXJDlQElCzTMVYE10M89Nicm3DZDhmfylkwc\n" +
            "hFfgVMulfzUYDaGnkeloIthlXpP4XVNgy65Nxgdiy48cr8oTLr1VLhS3bmjTZ06l\n" +
            "j13SYCOF7fvAkLyemfwuP4820G+O/a3s1PXZpLxcbskP1YsaOr6+Fg8ISt0d5MTc\n" +
            "J673AgMBAAGjKTAnMBEGCisGAQQBgsQKAwMEAwUEAzASBgNVHRMBAf8ECDAGAQH/\n" +
            "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQBbhnk9HZqNtSeqgfVfwyYcJmdd+wD0zQSr\n" +
            "NBH4V9JKt3/Y37vlGLNvYWsGhz++9yrbFjlIDaFCurab7DY7vgP1GwH1Jy1Ffc64\n" +
            "bFUqBBTRLTIaoxdelVI1PnZHIIvzzjqObjQ7ee57g/Ym1hnpNHuNZRim5UUlmeqG\n" +
            "tdWwtD4OJMTjpgzHrWb1CqGe0ITdmNNdvb92wit83v8Hod/x94R00WjmfhwKPiwX\n" +
            "m/N+UGxryl68ceUsw2y9WUwixxSMR8uQcym6a13qmttwzGnLJrE1db5lY7GP5eNp\n" +
            "kyWsmr0BKxvdB+4EyJgg2MHFTwGtp1BYuNnL7G2sFJ0DNSIj9pg/MA0GCSqGSIb3\n" +
            "DQEBCwUAA4IBAQA9XFFTK7knW7aoQgLfNdAHbt3oZaawIdpyArm76eKiGBVV+a17\n" +
            "HIr19nSNllzE97zusbpl3n7mr/pmrtQEmZDpjRxxjXGaYGybiMB+bkemXI14AM0E\n" +
            "kVm3rhM79vsnygXY5mjdY/DJvSbSfXSl5vQZjOZQWHlLb5bbv+ng2ATdK7Rg8kHb\n" +
            "vxml6NVqnuIP8X2J4YzPz1v1RIedMfpJsnTVMey1Shb+BkLW7GH4uZykn75oy1PB\n" +
            "IZwtVzewwUQ9q5K+kpz6YFsWnNHclitGEp8D5iNMoLNHu+bZhkvC5Fz7oNww+W07\n" +
            "Oq0a7fphvaY3PqAsU4JOFVw55ukrXnUSof+z\n" +
            "-----END CERTIFICATE REQUEST-----\n";

        _yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIIGxDCCBkoCAQAwFjEUMBIGA1UEAxMLVGFtZU15Q2VydHMwdjAQBgcqhkjOPQIB\n" +
            "BgUrgQQAIgNiAASPtRhIdI99BJMO7gqUGQEboby1f8GOVlcI8a5ScogUYTMUVGra\n" +
            "uGgJB0YAmSmAW+Z6h+23CDxtMPXZdyBQHeZ6Ly1vtHHZQUcWPIOQ5SPFXH+ot1YW\n" +
            "XDKmaYEAPh/f1pegggWzMIIFrwYJKoZIhvcNAQkOMYIFoDCCBZwwggKGBgorBgEE\n" +
            "AYLECgMLBIICdjCCAnIwggFaoAMCAQICEAEEYyJyfmBGMqFqLNuvdUowDQYJKoZI\n" +
            "hvcNAQELBQAwITEfMB0GA1UEAwwWWXViaWNvIFBJViBBdHRlc3RhdGlvbjAgFw0x\n" +
            "NjAzMTQwMDAwMDBaGA8yMDUyMDQxNzAwMDAwMFowJTEjMCEGA1UEAwwaWXViaUtl\n" +
            "eSBQSVYgQXR0ZXN0YXRpb24gOWMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASPtRhI\n" +
            "dI99BJMO7gqUGQEboby1f8GOVlcI8a5ScogUYTMUVGrauGgJB0YAmSmAW+Z6h+23\n" +
            "CDxtMPXZdyBQHeZ6Ly1vtHHZQUcWPIOQ5SPFXH+ot1YWXDKmaYEAPh/f1pejTjBM\n" +
            "MBEGCisGAQQBgsQKAwMEAwUHATAUBgorBgEEAYLECgMHBAYCBAHKZuowEAYKKwYB\n" +
            "BAGCxAoDCAQCAwIwDwYKKwYBBAGCxAoDCQQBAzANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
            "lEPdEAHnuNB99Rn645SVhaJFYeNmyaZRLWgRUoSbdJyTVrlMmPcWMOeY22HX9pU6\n" +
            "fvjx3nQqfBGzT9zWbayHpttlzhI21BQt8gFFvU6mbdQNwP4pSM6AYmbBcPmaEM19\n" +
            "XF8qF5Qs0+Y9B49eDa0peqcUEliQFL3jI4nE31rWWvqzkTo8eCBBB9Mh4jGEaEJt\n" +
            "kmCdNal2ufi+2RN83JHa4gL2eNMPx6y7kDXsdUgWLv432RwCmkGNnm3igsc3Qi4T\n" +
            "UD8YKcdb2RQlI5Fj8dpRIIqfQlmvW6LsrFJlzmDDulDzjWNH/bYSr7x4aZ/iR0nn\n" +
            "KXgxa2vZNe4YVIAMpLo3jDCCAw4GCisGAQQBgsQKAwIEggL+MIIC+jCCAeKgAwIB\n" +
            "AgIJAJbTv/X9sp96MA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1YmljbyBQ\n" +
            "SVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoYDzIwNTIw\n" +
            "NDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2fcZqRa70rTbNC2nfZUZpF6N\n" +
            "MENr0b6fxslEzDA83oBSqPckoGmyf+WzGhvdn8b6BGcfmppRv4+yXyT0A2Yr1NDT\n" +
            "bG331lSzZ2Rz0AXl5WZNayd1dQJa2V5vFi6N+tP6wa0L6UnHA6xOXSR3Cw8dMWmt\n" +
            "t5F+Pf9xLK6Lb2pqwVmJ6rpxO18/uPIaWJMBvICTiFX247xmLroJSOp00Uhsrehq\n" +
            "Oj06DAl53p0D0lAdWgm5JUDn97DnPf7/EBmV/FYQ7n9MGs3C7GoplXtS+VsAZRlj\n" +
            "x3bC/S8cEiAAXa8OnG1zku0jszzxsautyWIAQ8Xc8J3a0rPa28DyxtucYuCBAwID\n" +
            "AQABoykwJzARBgorBgEEAYLECgMDBAMFBwEwEgYDVR0TAQH/BAgwBgEB/wIBADAN\n" +
            "BgkqhkiG9w0BAQsFAAOCAQEArOa4M8CaOw7/Ck/Hp6gTXCJsLM3vVu45qiLDPuP7\n" +
            "Dh7uK5+QJfMODDsx1eSsv1r+6UgpCVEzKkmgQX8Hr7wmsm6q6Tcr3vaF6S2XBici\n" +
            "/j5ZM36Wc5KaN0y/uBLGUy0213/ncRLxZoRGwksDJR+67CpMC5YYA3SobTHnzc+Z\n" +
            "u8/QC2acnuz72KU8MbowbrCUq88vRS9sH5/cAFv/WVVFz7oU4ekRNRSL+n8GOB1i\n" +
            "7LddzM8UzVmbx8bayGbJbwFSP4FS4skrmfYfMbgd8k0gMePHFlx6DYJpa7lTW1cJ\n" +
            "NjdDYpjoqzmgr1xgVbAb7vWY4OyQ0v0eBJRQJKfX8GQo0TAKBggqhkjOPQQDAwNo\n" +
            "ADBlAjAHToN7Un4UWV37px8WBdmXT/QkmhPTGEnZIf15A0PEIgOzlWJr9UPIphSg\n" +
            "UlIxjH4CMQDCIY2BUxFRNejz+acAsrMBs/ZFRBRLyXTBG7FqmHTnZoOG8C3g1SXt\n" +
            "S2tYi7825f8=\n" +
            "-----END CERTIFICATE REQUEST-----\n";

        _yubikey_valid_5_4_3_Once_Cached_UsbAKeychain_9a_FIPS_RSA_2048_CSR =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIIJATCCB7kCAQAwFjEUMBIGA1UEAxMLVGFtZU15Q2VydHMwggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQDeOyoR9WOrkZnop6csbCcg56iTZIphvzwacn0f\n" +
            "FCjB/KlvxiUOfnT6cPEowHybdq3Uf9eAP7VRvJC96CAiaWnDwiGAHf9VPNAcoWKY\n" +
            "mTWKhGpNXEb2mzn/wFfKaEmZbePuvgCSGAg4F15maIkAoD4FuBlgVXNnRs2d0SRg\n" +
            "/cNVlTAntXEgNed8l26845lB9uwu/lFRQNMN5QlzoDowslDts4GUeQukwhJPM3IG\n" +
            "3dv2PyofL6W7XPt2RyWAh9/sgI/Hv8LnNN+X9IjtkfoNj7AEpwOlj0m0pVc6PErt\n" +
            "bDtMPN+b8dvDHiISoUYMOSEK6ntVj/1QJ4LtINNsHTduWOJ9AgMBAAGgggZ0MIIG\n" +
            "cAYJKoZIhvcNAQkOMYIGYTCCBl0wggM0BgorBgEEAYLECgMLBIIDJDCCAyAwggII\n" +
            "oAMCAQICEAGGZrGxJU5oBjuULRfjUpgwDQYJKoZIhvcNAQELBQAwITEfMB0GA1UE\n" +
            "AwwWWXViaWNvIFBJViBBdHRlc3RhdGlvbjAgFw0xNjAzMTQwMDAwMDBaGA8yMDUy\n" +
            "MDQxNzAwMDAwMFowJTEjMCEGA1UEAwwaWXViaUtleSBQSVYgQXR0ZXN0YXRpb24g\n" +
            "OWEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDeOyoR9WOrkZnop6cs\n" +
            "bCcg56iTZIphvzwacn0fFCjB/KlvxiUOfnT6cPEowHybdq3Uf9eAP7VRvJC96CAi\n" +
            "aWnDwiGAHf9VPNAcoWKYmTWKhGpNXEb2mzn/wFfKaEmZbePuvgCSGAg4F15maIkA\n" +
            "oD4FuBlgVXNnRs2d0SRg/cNVlTAntXEgNed8l26845lB9uwu/lFRQNMN5QlzoDow\n" +
            "slDts4GUeQukwhJPM3IG3dv2PyofL6W7XPt2RyWAh9/sgI/Hv8LnNN+X9IjtkfoN\n" +
            "j7AEpwOlj0m0pVc6PErtbDtMPN+b8dvDHiISoUYMOSEK6ntVj/1QJ4LtINNsHTdu\n" +
            "WOJ9AgMBAAGjTjBMMBEGCisGAQQBgsQKAwMEAwUEAzAUBgorBgEEAYLECgMHBAYC\n" +
            "BAG6WQYwEAYKKwYBBAGCxAoDCAQCAgMwDwYKKwYBBAGCxAoDCQQBgTANBgkqhkiG\n" +
            "9w0BAQsFAAOCAQEArE7iI5PZjIYtCVQ2qrOL6QD9szE+3DhzA9WBoT77kBSqL3Xe\n" +
            "T/I/WI4Eq6wZziu+uFsy3EuCVKu2CfVVAGFtvL+icnrcyreYAjdL48KmsePFk+jd\n" +
            "o/4w4eWUTcWY+09TSetajnnHTQ+cR4EltbyklEKRyHfIjU9e1ctHxYWJM86GOLeR\n" +
            "7tklp+crKTDNAcFzIyM/CMS0OfnafjzKsvVI8DvLTeyUtwQw/QOV+aPWFVCxdjqq\n" +
            "NvsPuQtgiokiV3QggYu/Fr0fJyp+FE/1wtHUEqQWrODK0mAn13MWMtj1D+KK2XjS\n" +
            "E/w1r05lFaQQqcJ2AQtkgBONaGqZJNlVjsIIGzCCAyEGCisGAQQBgsQKAwIEggMR\n" +
            "MIIDDTCCAfWgAwIBAgIJAJrfc9rkKdzuMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV\n" +
            "BAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw\n" +
            "MDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0\n" +
            "dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyxuU2atQ\n" +
            "MWgdBUJ/9ebFvorSlQC0ia6a9mDSnh9AAhUbwy89MC1GNKb+Blrqx+A/LHokn289\n" +
            "mGZ2dGEw1LZhiLC0m2KpGCoin2Cx3T1w3VNHzFFezTatYDwLvx1p250odzJJWRBD\n" +
            "pUGr9ey+mMz9v0byyLt3Zsy/vlzgZZfzswxDtLOXSz02pxQ2fLGzt7Ayw57ip1hP\n" +
            "AtrKjfAaA82z8fZZ9yvl2Fo+Tu/kCk1AG/2tfPXGLXSrZgwYUKlUohtBMLeaocJc\n" +
            "q3ympCdICuqykMq5YYjek9Gf6XLpc6AdYtyVaGBo0LubUBTu6LA7yPjOQYElCu0V\n" +
            "+lqCjVjFGgcbsQIDAQABozwwOjARBgorBgEEAYLECgMDBAMFBAMwEQYKKwYBBAGC\n" +
            "xAoDCgQDAgEHMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQELBQADggEB\n" +
            "AGXyYgCspGVK12JwEbj6zFrNHttekQXI9lbYLdywZEw5xDBgQ3VtDm45naR9Nt0/\n" +
            "w4NmUxo6z2sw9/5tBsAr/RF+LFp+9Gv8qm/wXwYMZD2g+2RiujY0WeXIss9nS3t9\n" +
            "8G/B5OO5ePAKb2eTt3NfgX5wsigbY4KH1XibjuNZmcLJyaWwxQAImR9ibnqeLw9W\n" +
            "mm/jVJ3JA3u5WPNohbme39pX4dDdHTOvdmkaYcXr373HxTFRXM/D37jqrHBXy55S\n" +
            "pgX7kjtedi7QL2f+FymWu41topVIeFL4jTXEtgFqX4cpSpvSLW2W2+H+uvA4QoLy\n" +
            "rJno24gpVaPaAgPB6YUedZcwPQYJKoZIhvcNAQEKMDCgDTALBglghkgBZQMEAgGh\n" +
            "GjAYBgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBogMCASADggEBADIDrl526qQMXSn8\n" +
            "ADsKiQ8D4fPTaAnuecivKu7rplZDptLvCDu/1tduIgz6osNvsEsGgWjFWDDFTq4s\n" +
            "PwmEdxxFHsTDbTEYdEuowubPw33Tj2FCwy3yHFGGUxXZTYAE1g+/9AcoL8M2zmfp\n" +
            "/GP5+ha52/GPqmkB1KbEL8XzlucpMGRi+n0zFf33lhXeN4r0DP8aVHNxcBN4wyw3\n" +
            "gLHyB5Sob3b6b0qLKTFAE91MY3h+GSrMXW3uLlI+a5o5QHlkZ2M4wARb003Mqbmc\n" +
            "BBIbMd9kK+Np20xMNNRXBK7X37ISmMNBfNmT0zPZ7gq80Shts5Y7wDLR2lWax8II\n" +
            "4gDDulQ=\n" +
            "-----END CERTIFICATE REQUEST-----\n";

        _yubikey_valid_5_4_3_Always_Never_UsbAKeychain_9a_Normal_ECC_384_CSR =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIIGaTCCBhACAQAwFjEUMBIGA1UEAxMLVGFtZU15Q2VydHMwWTATBgcqhkjOPQIB\n" +
            "BggqhkjOPQMBBwNCAASa4hAbXsJat9RysMXDryp5eatzJhXtxpgyTwNgXXZUAoLg\n" +
            "38xR0UIYHrM40ai7z527LiK5YUpzbFVPUCarGYRboIIFljCCBZIGCSqGSIb3DQEJ\n" +
            "DjGCBYMwggV/MIICaQYKKwYBBAGCxAoDCwSCAlkwggJVMIIBPaADAgECAhABoGQP\n" +
            "roLjaTWRZ0ShE3t+MA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMMFll1YmljbyBQ\n" +
            "SVYgQXR0ZXN0YXRpb24wIBcNMTYwMzE0MDAwMDAwWhgPMjA1MjA0MTcwMDAwMDBa\n" +
            "MCUxIzAhBgNVBAMMGll1YmlLZXkgUElWIEF0dGVzdGF0aW9uIDlhMFkwEwYHKoZI\n" +
            "zj0CAQYIKoZIzj0DAQcDQgAEmuIQG17CWrfUcrDFw68qeXmrcyYV7caYMk8DYF12\n" +
            "VAKC4N/MUdFCGB6zONGou8+duy4iuWFKc2xVT1AmqxmEW6NOMEwwEQYKKwYBBAGC\n" +
            "xAoDAwQDBQQDMBQGCisGAQQBgsQKAwcEBgIEASwDdzAQBgorBgEEAYLECgMIBAID\n" +
            "ATAPBgorBgEEAYLECgMJBAEBMA0GCSqGSIb3DQEBCwUAA4IBAQBQiEJ8rtn5AKCA\n" +
            "SX8bqyYKoDS+h/PfFqBhRSY+y5nmVCqSwtZ7lm9/2bRtWwyGJ/xIRqBe8H1maUGl\n" +
            "7x3ZEjCtZ48MJiAzrF0t2icB9N334XSUiHKranMWhjYhS7FY+kvQSMmxh0igGbB5\n" +
            "kQWnO1QPzcgy1eEL6XLHuQxwZyOOTGI0C0oLJRpWxS262jRtWEQ7OdG7IgLrhsJL\n" +
            "TrG0upuMKv9fL21cRT9cMfFlLSSIeiUXXOAOgMJ4NTuGuoNXpn0D7AkrlH0HaMBl\n" +
            "D5NqwGwEML+inBuVkIzAc2KxWZllBu8BQzdX85kTgsP4cWbLXdiht7Rub2A68reR\n" +
            "79IxVENoMIIDDgYKKwYBBAGCxAoDAgSCAv4wggL6MIIB4qADAgECAgkA6MPdeZ5D\n" +
            "O2IwDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgWXViaWNvIFBJViBSb290IENB\n" +
            "IFNlcmlhbCAyNjM3NTEwIBcNMTYwMzE0MDAwMDAwWhgPMjA1MjA0MTcwMDAwMDBa\n" +
            "MCExHzAdBgNVBAMMFll1YmljbyBQSVYgQXR0ZXN0YXRpb24wggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQC9PT4n9BHqypwVUo2qvOyQUG96nZZpArJfgc/t\n" +
            "As8/Ylk2brMQjHIi0B8faIRbjrSsOS6vVk6ZX+P/cX1tR1a2hKZ+hbaUuC6wETPQ\n" +
            "WA5LzWm/PqFx/b6Zbwp6B29moNtEjY45d3e217QPjwlrwPjHTmmPZ8xZh7x/lirc\n" +
            "GO+ezkC2VXJDlQElCzTMVYE10M89Nicm3DZDhmfylkwchFfgVMulfzUYDaGnkelo\n" +
            "IthlXpP4XVNgy65Nxgdiy48cr8oTLr1VLhS3bmjTZ06lj13SYCOF7fvAkLyemfwu\n" +
            "P4820G+O/a3s1PXZpLxcbskP1YsaOr6+Fg8ISt0d5MTcJ673AgMBAAGjKTAnMBEG\n" +
            "CisGAQQBgsQKAwMEAwUEAzASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEB\n" +
            "CwUAA4IBAQBbhnk9HZqNtSeqgfVfwyYcJmdd+wD0zQSrNBH4V9JKt3/Y37vlGLNv\n" +
            "YWsGhz++9yrbFjlIDaFCurab7DY7vgP1GwH1Jy1Ffc64bFUqBBTRLTIaoxdelVI1\n" +
            "PnZHIIvzzjqObjQ7ee57g/Ym1hnpNHuNZRim5UUlmeqGtdWwtD4OJMTjpgzHrWb1\n" +
            "CqGe0ITdmNNdvb92wit83v8Hod/x94R00WjmfhwKPiwXm/N+UGxryl68ceUsw2y9\n" +
            "WUwixxSMR8uQcym6a13qmttwzGnLJrE1db5lY7GP5eNpkyWsmr0BKxvdB+4EyJgg\n" +
            "2MHFTwGtp1BYuNnL7G2sFJ0DNSIj9pg/MAoGCCqGSM49BAMCA0cAMEQCIHoAN963\n" +
            "Jwhzf7EkenWe2R2m9slB2OWIBRB5TMUBWSDiAiAkwSNRUjDbWJIP3gNmmnrpJuaj\n" +
            "nmObx+OfPQaCUoMxZw==\n" +
            "-----END CERTIFICATE REQUEST-----\n";

        _policy = new CertificateRequestPolicy
        {
            YubikeyPolicy = [new YubikeyPolicy()]
        };

        _yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_dbRow =
            new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
                CertCli.CR_IN_PKCS10);
        _yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_dbRow =
            new CertificateDatabaseRow(_yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR,
                CertCli.CR_IN_PKCS10);
        _yubikey_valid_5_4_3_Once_Cached_UsbAKeychain_9a_FIPS_RSA_2048_dbRow =
            new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Cached_UsbAKeychain_9a_FIPS_RSA_2048_CSR,
                CertCli.CR_IN_PKCS10);

        _output = output;
        _listener = new ETWLoggerListener();

        _ykValidator = new YubikeyValidator([_yubikeyPivRootCaSerial263751]);
    }

    internal void PrintResult(CertificateRequestValidationResult result, YubikeyObject yubikey = null)
    {
        _output.WriteLine("0x{0:X} ({0}) {1}.", result.StatusCode,
            new Win32Exception(result.StatusCode).Message);
        _output.WriteLine(string.Join("\n", result.Description));
        if (yubikey != null)
        {
            _output.WriteLine(yubikey.SaveToString());
        }
    }

    private string Retrieve_CSR_from_Resource(string resourceName)
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(resourceName);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    [Fact]
    public void Does_return_if_already_denied()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10002);
        var result = new CertificateRequestValidationResult(dbRow);

        result.SetFailureStatus(WinError.ERROR_INVALID_TIME);

        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        result = _ykValidator.VerifyRequest(result, _policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_INVALID_TIME));
    }

    [Fact]
    public void Does_return_if_no_Yubikey_policy()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10002);
        var result = new CertificateRequestValidationResult(dbRow);

        var policy = new CertificateRequestPolicy();

        result = _ykValidator.GetYubikeyObject(result, policy, dbRow, out var yubikey);
        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Denies_when_CSR_does_not_contain_attestation()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        var csr =
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

        var dbRow = new CertificateDatabaseRow(csr, CertCli.CR_IN_PKCS10, null, 10002);
        var result = new CertificateRequestValidationResult(dbRow);

        var policy = _policy;
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.7.1";

        result = _ykValidator.GetYubikeyObject(result, policy, dbRow, out var yubikey);
        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.Null(yubikey);
        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Denies_when_CSR_does_contain_invalid_attestation()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // contains attestation extension with invalid content
        var csr =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIErzCCAxcCAQAwGTEXMBUGA1UEAxMOdGhpcy1pcy1hLXRlc3QwggGiMA0GCSqG\n" +
            "SIb3DQEBAQUAA4IBjwAwggGKAoIBgQDegFRHhe0PQ3aRjNtXrFelJkkiuQpjSLbp\n" +
            "D6ghZMQpc2NpHlpidWIZfSKHSk5s6l9o3p/nn4hTzI80QVOWNDSY/vqQI5mb9uYc\n" +
            "3YhDADU1atD4DW/EUsTTM3z9YuRcJOVOtPpqQtWh1y+flw6VhG/Z/Ho9WcwPx+nE\n" +
            "9moEQWP2v+2rOiTEplxhnF4GvDjKMMPzqakWtvAN+OzY8pQB7D0P37eATierIQiB\n" +
            "eO8wpcE7pMeV/CHZ9qVAxN++Z5Afb+icyAaXlrZHzFglfF97Pi3ro1zCaTsMRItX\n" +
            "OQ4xUbfdlmrDENhjwNrpOadHlSo6nfE/B7H/0yy5we2K2NozIYRE9aHvuhDt8kkU\n" +
            "irMWUMMYMDwo+zXDaGUSKjyiQZ6+9MmLGRF0C6LSbHXLpoJLVrEg9y9T5QyAySBc\n" +
            "i3AMeTT7nmx5s4vgvos0jRGuOA81lbCpcE265aF13VoqcA4xy0sWrxHMAPkCKkPi\n" +
            "QVQXzphL/w3JEWOC5XkP8Qcvg+n9skkCAwEAAaCCAU8wHAYKKwYBBAGCNw0CAzEO\n" +
            "FgwxMC4wLjI2MTAwLjIwMAYJKwYBBAGCNxUUMSMwIQIBBQwGREVWLVBDDApERVYt\n" +
            "UENcdXdlDAhwd3NoLmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIA\n" +
            "bwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEA\n" +
            "ZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMIGUBgkqhkiG9w0BCQ4xgYYwgYMwDgYD\n" +
            "VR0PAQH/BAQDAgeAMCgGCisGAQQBgsQKAwsEGjAYMBagFKAShhBzb21lLXJhbmRv\n" +
            "bS1kYXRhMCgGCisGAQQBgsQKAwIEGjAYMBagFKAShhBzb21lLXJhbmRvbS1kYXRh\n" +
            "MB0GA1UdDgQWBBQH3S8W+wgSqrm2seOW3XXDPzEmMzANBgkqhkiG9w0BAQsFAAOC\n" +
            "AYEAw1Sc7zQkWXNyTIpo8+VXJKOViGcguGt2A4V1R6TNgP3H8zZAijz13BZpcA6x\n" +
            "1/LBTXjMxRRkYQJl6GztM54NjJBl3k8ybK9mXeUNEjHtUyxQFnh1dWNVZCdm0gkS\n" +
            "qRvfoD3yEJt0jGetp6aKen1AybIV+m/eh+WpZUPZEgbsSHXRmIMIu88JD9msn8Ar\n" +
            "VG2N26ud7omDmLHG5BMYglJ65mrwyoIEMF0rsXTG1oNiO3UA0f2i69/7vo7NO0On\n" +
            "KUDimMhK2vobbhxq38ZtRmNDCoNHUEsorDtWIJj+GNljI7RtClfoEe0FANQYZNNs\n" +
            "39554J3jM80o7BnadMmissR2QL8DZcrxwQN6Od6kuEojI2/eRAPZrWkUnL1q6HkZ\n" +
            "B43vWGxasGY9uX7GYNh9IxViuz/xZJUg7j/LLkuVrP9kFZM8rjHiztdNIZUvrIoj\n" +
            "83FJD4P3StpkWuSnwh/FQcJHwAFn/l3fVYfDe56FJvsZgV/L5BYKE9uqf7Ax/aFn\n" +
            "rNsE\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(csr, CertCli.CR_IN_PKCS10, null, 10002);
        var result = new CertificateRequestValidationResult(dbRow);

        var policy = _policy;
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.7.1";

        result = _ykValidator.GetYubikeyObject(result, policy, dbRow, out var yubikey);
        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.Null(yubikey);
        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.NTE_FAIL));
    }

    [Fact]
    public void Extract_Genuine_Yubikey_Attestation_10001()
    {
        _listener.ClearEvents();
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10001);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        PrintResult(result, yubikey);

        Assert.True(yubikey.TouchPolicy == YubikeyTouchPolicy.NEVER);
        Assert.True(yubikey.PinPolicy == YubikeyPinPolicy.ONCE);
        Assert.True(yubikey.FirmwareVersion == new Version(5, 4, 3));
        Assert.True(yubikey.FormFactor == YubikeyFormFactor.USB_A_KEYCHAIN);
        Assert.True(yubikey.Slot == "9a");

        // Validate that we get a debug message with the attestation OID information
        Assert.Contains(4209, _listener.Events.Select(e => e.EventId));
        // Validate that the 4209 says that the attestation comes from the faulty PIVTOOL OID
        Assert.Equal(YubikeyX509Extension.ATTESTATION_DEVICE_PIVTOOL,
            _listener.Events.First(x => x.EventId == 4209).Payload[1].ToString());
    }

    [Fact]
    public void Validate_Policy_MinimumFirmware_5_7_1_should_Reject_10002()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10002);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.7.1";

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Validate_Policy_MinimumFirmware_5_7_1_should_Allow_10003()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10003);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.7.1";

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Does_add_attestation_extensions_to_issued_certificate()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10003);
        var result = new CertificateRequestValidationResult(dbRow);

        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        result = _ykValidator.VerifyRequest(result, _policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);

        Assert.True(result.CertificateExtensions.ContainsKey(YubikeyX509Extension.FIRMWARE));
        Assert.True(result.CertificateExtensions.ContainsKey(YubikeyX509Extension.FORMFACTOR));
        Assert.True(result.CertificateExtensions.ContainsKey(YubikeyX509Extension.PIN_TOUCH_POLICY));
        Assert.True(result.CertificateExtensions.ContainsKey(YubikeyX509Extension.SERIALNUMBER));

        Assert.Equivalent(
            yubikey.AttestationCertificate.Extensions
                .FirstOrDefault(x => x.Oid.Value.Equals(YubikeyX509Extension.FIRMWARE)).RawData,
            result.CertificateExtensions.FirstOrDefault(x => x.Key.Equals(YubikeyX509Extension.FIRMWARE)).Value
        );

        Assert.Equivalent(
            yubikey.AttestationCertificate.Extensions
                .FirstOrDefault(x => x.Oid.Value.Equals(YubikeyX509Extension.FORMFACTOR)).RawData,
            result.CertificateExtensions.FirstOrDefault(x => x.Key.Equals(YubikeyX509Extension.FORMFACTOR)).Value
        );

        Assert.Equivalent(
            yubikey.AttestationCertificate.Extensions
                .FirstOrDefault(x => x.Oid.Value.Equals(YubikeyX509Extension.PIN_TOUCH_POLICY)).RawData,
            result.CertificateExtensions.FirstOrDefault(x => x.Key.Equals(YubikeyX509Extension.PIN_TOUCH_POLICY)).Value
        );

        Assert.Equivalent(
            yubikey.AttestationCertificate.Extensions
                .FirstOrDefault(x => x.Oid.Value.Equals(YubikeyX509Extension.SERIALNUMBER)).RawData,
            result.CertificateExtensions.FirstOrDefault(x => x.Key.Equals(YubikeyX509Extension.SERIALNUMBER)).Value
        );
    }

    [Fact]
    public void Validate_PIN_Policy_Once_should_Allow_10004()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10004);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].PinPolicies.Add(YubikeyPinPolicy.ONCE);

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_PIN_Policy_Deny_Never_should_Allow_10005()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10005);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].PinPolicies.Add(YubikeyPinPolicy.NEVER);
        policy.YubikeyPolicy[0].Action = PolicyAction.DENY;

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);
        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_PIN_Policy_Deny_Once_should_Deny_10006()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10006);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].PinPolicies.Add(YubikeyPinPolicy.ONCE);
        policy.YubikeyPolicy[0].Action = PolicyAction.DENY;

        _listener.ClearEvents();

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.Single(_listener.Events); // Ensure one event was logged
        Assert.Equal(4201, _listener.Events[0].EventId);
        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Validate_FIPS_Edition_Should_Deny_10007()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10007);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        var policy = _policy;
        policy.YubikeyPolicy[0].Edition.Add(YubikeyEdition.FIPS);

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);
        PrintResult(result, yubikey);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Validate_FIPS_Edition_Should_Allow_10008()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Cached_UsbAKeychain_9a_FIPS_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10008);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].Edition.Add(YubikeyEdition.FIPS);

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);
        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_PIN_Policy_VerifyAll_10009()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10009);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].PinPolicies.Add(YubikeyPinPolicy.ONCE);
        policy.YubikeyPolicy[0].TouchPolicies.Add(YubikeyTouchPolicy.NEVER);
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.4.0";
        policy.YubikeyPolicy[0].MaximumFirmwareString = "5.7.0";
        policy.YubikeyPolicy[0].FormFactor.Add(YubikeyFormFactor.USB_A_KEYCHAIN);
        policy.YubikeyPolicy[0].Edition.Add(YubikeyEdition.NORMAL);
        policy.YubikeyPolicy[0].KeyAlgorithmFamilies.Add(KeyAlgorithmFamily.RSA);

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Touch_Policy_Allow_Never_should_Allow_10010()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10010);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].TouchPolicies.Add(YubikeyTouchPolicy.NEVER);

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Touch_Policy_Deny_Never_should_Deny_10011()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10011);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].TouchPolicies.Add(YubikeyTouchPolicy.NEVER);
        policy.YubikeyPolicy[0].Action = PolicyAction.DENY;

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Validate_Touch_Policy_Allowed_Always_should_Deny_10012()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10012);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].TouchPolicies.Add(YubikeyTouchPolicy.ALWAYS);

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Validate_Require_Firmware_Above_5_7_1_to_allow_ECC_should_allow_10013()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10013);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].KeyAlgorithmFamilies.Add(KeyAlgorithmFamily.ECC);
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.7.1";

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Require_Firmware_Above_5_7_1_to_allow_ECC_should_deny_10016()
    {
        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Always_Never_UsbAKeychain_9a_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10016);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].KeyAlgorithmFamilies.Add(KeyAlgorithmFamily.ECC);
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.7.1";

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.Contains(4203, _listener.Events.Select(e => e.EventId));
        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Validate_Deny_Firmware_Below_5_6_9_with_ECC_should_deny_10017()
    {
        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Always_Never_UsbAKeychain_9a_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10017);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].KeyAlgorithmFamilies.Add(KeyAlgorithmFamily.ECC);
        policy.YubikeyPolicy[0].MaximumFirmwareString = "5.6.9";
        policy.YubikeyPolicy[0].Action = PolicyAction.DENY;

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.Contains(4201, _listener.Events.Select(e => e.EventId));
        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Validate_Deny_Firmware_Below_5_6_9_with_ECC_should_allow_10018()
    {
        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10018);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].KeyAlgorithmFamilies.Add(KeyAlgorithmFamily.ECC);
        policy.YubikeyPolicy[0].MaximumFirmwareString = "5.6.9";
        policy.YubikeyPolicy[0].Action = PolicyAction.DENY;

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Deny_wrong_KeyAlgorithmFamily_should_deny()
    {
        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10018);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].KeyAlgorithmFamilies.Add(KeyAlgorithmFamily.RSA);
        policy.YubikeyPolicy[0].Action = PolicyAction.ALLOW;

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }


    [Fact]
    public void Set_Subject_RDN_to_Yubikey_Slot_10019()
    {
        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10019);
        var policy = _policy;
        policy.OutboundSubject.Add(new OutboundSubjectRule
        {
            Field = RdnTypes.CommonName,
            Value = "{yk:slot}",
            Mandatory = true,
            Force = true
        });

        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, policy, dbRow, out var yubikey);
        result = _ccValidator.VerifyRequest(result, policy, dbRow, null, _caConfig, yubikey);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
        Assert.Contains("9c",
            result.CertificateProperties.Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.CommonName]))
                .Select(x => x.Value));
    }

    [Fact]
    public void Rewrite_Subject_to_slot_10014()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10014);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.OutboundSubject.Add(new OutboundSubjectRule
            {
                Field = RdnTypes.CommonName,
                Value = "{yk:slot}",
                Mandatory = true,
                Force = true
            }
        );

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);
        result = _ccValidator.VerifyRequest(result, policy,
            _yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_dbRow, null, _caConfig, yubikey);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
        Assert.Contains("9a", result.CertificateProperties
            .Where(x => x.Key.Equals(RdnTypes.NameProperty[RdnTypes.CommonName]))
            .Select(x => x.Value));
    }

    [Fact]
    public void Validate_Actual_Attestations_certificate_wrong_public_key_10015()
    {
        #region CSR

        const string csr =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIIGhjCCBi0CAQAwFjEUMBIGA1UEAxMLVGFtZU15Q2VydHMwWTATBgcqhkjOPQIB\n" +
            "BggqhkjOPQMBBwNCAAQL7vD+BWCz9dE3w4LWyHynw26z+QjK6Mm6wKkGvnpAYY2R\n" +
            "di8Dt01qG5X5art1njoS9gOvRbFnKHvHUwnPSOKooIIFszCCBa8GCSqGSIb3DQEJ\n" +
            "DjGCBaAwggWcMIIChgYKKwYBBAGCxAoDCwSCAnYwggJyMIIBWqADAgECAhAB8pev\n" +
            "E7/utfqJv2eZc/edMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMMFll1YmljbyBQ\n" +
            "SVYgQXR0ZXN0YXRpb24wIBcNMTYwMzE0MDAwMDAwWhgPMjA1MjA0MTcwMDAwMDBa\n" +
            "MCUxIzAhBgNVBAMMGll1YmlLZXkgUElWIEF0dGVzdGF0aW9uIDlhMHYwEAYHKoZI\n" +
            "zj0CAQYFK4EEACIDYgAEi8t88XhiXfaC1S7+rfkmLIQMm4HS8wa4O8Su4JvIxEoK\n" +
            "rQd5C3JvRFa4wiLn72OD3VDuNB22RfxBQxBJn9dl/VtPZbhf1uMVIBQeo2V66KvW\n" +
            "44TUKRdCyMJ+nveIPO5to04wTDARBgorBgEEAYLECgMDBAMFBwEwFAYKKwYBBAGC\n" +
            "xAoDBwQGAgQBymbqMBAGCisGAQQBgsQKAwgEAgMCMA8GCisGAQQBgsQKAwkEAQMw\n" +
            "DQYJKoZIhvcNAQELBQADggEBAAtzgqRrrmrLIrS8+ZAj9DXOakG1Z+1y+FRNxCfK\n" +
            "KG7ukpB9p4Nl1mJGy/39/af4tRrG5PfUB67FhTasRADBCpm9MiQOxTgpydLrco6U\n" +
            "3t2g+0vw+4ic0BtqRgy+IZWW3nIaLhnRAtM80jjSsAwH10hQc0kiFgkZ1znlrV2M\n" +
            "HX1BU4IesaOI6dT/tqpAqljdp75IR5wc4drbHlxjfSDxg7GkZq9iZrhEb0XK4oTq\n" +
            "/Enl6R2dO/W6YXCEFHlgaqmuByF4ICG6ajN34gnQYnbkqQ483Gz5TZ1QPP4f4KxV\n" +
            "3S8I2t1g0rbA17AKSEwxjEan2ke0C7uermbeRiMai56UzcUwggMOBgorBgEEAYLE\n" +
            "CgMCBIIC/jCCAvowggHioAMCAQICCQCW07/1/bKfejANBgkqhkiG9w0BAQsFADAr\n" +
            "MSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0EgU2VyaWFsIDI2Mzc1MTAgFw0x\n" +
            "NjAzMTQwMDAwMDBaGA8yMDUyMDQxNzAwMDAwMFowITEfMB0GA1UEAwwWWXViaWNv\n" +
            "IFBJViBBdHRlc3RhdGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
            "ANn3GakWu9K02zQtp32VGaRejTBDa9G+n8bJRMwwPN6AUqj3JKBpsn/lsxob3Z/G\n" +
            "+gRnH5qaUb+Psl8k9ANmK9TQ02xt99ZUs2dkc9AF5eVmTWsndXUCWtlebxYujfrT\n" +
            "+sGtC+lJxwOsTl0kdwsPHTFprbeRfj3/cSyui29qasFZieq6cTtfP7jyGliTAbyA\n" +
            "k4hV9uO8Zi66CUjqdNFIbK3oajo9OgwJed6dA9JQHVoJuSVA5/ew5z3+/xAZlfxW\n" +
            "EO5/TBrNwuxqKZV7UvlbAGUZY8d2wv0vHBIgAF2vDpxtc5LtI7M88bGrrcliAEPF\n" +
            "3PCd2tKz2tvA8sbbnGLggQMCAwEAAaMpMCcwEQYKKwYBBAGCxAoDAwQDBQcBMBIG\n" +
            "A1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQELBQADggEBAKzmuDPAmjsO/wpP\n" +
            "x6eoE1wibCzN71buOaoiwz7j+w4e7iufkCXzDgw7MdXkrL9a/ulIKQlRMypJoEF/\n" +
            "B6+8JrJuquk3K972hektlwYnIv4+WTN+lnOSmjdMv7gSxlMtNtd/53ES8WaERsJL\n" +
            "AyUfuuwqTAuWGAN0qG0x583PmbvP0AtmnJ7s+9ilPDG6MG6wlKvPL0UvbB+f3ABb\n" +
            "/1lVRc+6FOHpETUUi/p/BjgdYuy3XczPFM1Zm8fG2shmyW8BUj+BUuLJK5n2HzG4\n" +
            "HfJNIDHjxxZceg2CaWu5U1tXCTY3Q2KY6Ks5oK9cYFWwG+71mODskNL9HgSUUCSn\n" +
            "1/BkKNEwCgYIKoZIzj0EAwIDRwAwRAIgJi8zizb0MmkYFW3FHfU2RngAIK+kS+uw\n" +
            "iIv3qbQubxYCIFOtZseiiicTiReB+Tsh7RnkJx72zx71VE0XdbhroWl+\n" +
            "-----END CERTIFICATE REQUEST-----\n";

        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(csr, CertCli.CR_IN_PKCS10, null, 10015);

        #endregion

        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        var policy = _policy;

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.Contains(4207, _listener.Events.Select(e => e.EventId));

        Assert.Null(yubikey);
        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.NTE_FAIL));
    }

    [Fact]
    public void Denies_when_no_attestation_Root()
    {
        #region CSR

        var validator = new YubikeyValidator([]);

        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10015);

        #endregion

        var result = new CertificateRequestValidationResult(dbRow);
        result = validator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        var policy = _policy;

        result = validator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.Null(yubikey);
        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.NTE_FAIL));
    }

    [Fact]
    public void Denies_when_invalid_attestation_Root()
    {
        var testCa =
            "MIID4TCCAkmgAwIBAgIQHgSMPLxvPotB6kiqNq2UkTANBgkqhkiG9w0BAQsFADAS" +
            "MRAwDgYDVQQDEwdURVNUIENBMCAXDTI1MDMxNjE1MTYzOFoYDzIxMjUwMzE2MTUz" +
            "NjM4WjASMRAwDgYDVQQDEwdURVNUIENBMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A" +
            "MIIBigKCAYEAwbgnqrr5klqk3UokMwuGZikXMinUS6yngsrGEN/5TEhpHGcJgVOo" +
            "uJmLZJBmnip4r4lV+qUJCJkv6hgcyheP3yZPS2SlzxCdgGZJYr0gIneYRkwLss2f" +
            "8ibngZskQ93QEXfhdQ8BQ8ivY8vhbFoTiUZP4JVfqiDlPsXTvGQSYL7cSbF+EW/N" +
            "LfEIeTtoBovl2hbyLq52W5a/SRfVU6S2BvpwO+OlPOWyiJxcereqIXLDzSihUItW" +
            "9vMB1ESmmtsh8+QlR5eZ/gVIJaW/uPb5u3fSejjNtuFy0xjb36e5wjfGJP1YrdEe" +
            "vsNF9cQ4jinlGiY/Gb8cPWTUQwGx2fLo4ehPF7pkB8iZZ+h9pxZGORYYTSFcL+o1" +
            "xFc1NGFAmCxHJG/8Osh+EKTiNbw/qztf3rIaXxJdtVMtCZi5yJ8y2rl52/6km+xy" +
            "sVnYxp4GNKm5fOcFMCsT7M/2c+/JkRWgRWhYXH85Lwn8b/wsNK1306g3TcJfX8lD" +
            "wmGwgwPTre6pAgMBAAGjMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUtfwW" +
            "OKLU32tltoOfzSgvq7UBJuMwDQYJKoZIhvcNAQELBQADggGBALq4j7hLBmbvHMAV" +
            "p0zEcdwUokiDzWYkLZ+TsQCsSIi5nyUSIm2C2zQFrWw3u3krKwwkNPGabAxw8V6p" +
            "GXfjUYWJ0Y7MJHrqM5qeATAFl/0TG0yhc53mdo9FdG7s7LStlZEUBd5ZxhSXm1mt" +
            "/UyGooz8emJKGbE0zXQdKlZM+5Bwdy5xiabsfBgAZm8/Hu0C47GEF3cKWxrU7KWc" +
            "Kp6mIT1ATnhSDPOSliWrinyw7Vvs8IxEbUo6BszGFe1CD7De2I72RT+/5acl31+3" +
            "xDSOz5C2i/0MIMxotLDxpgX51QmbMEP4FLvkwPpEebDIY9kqsPhFoOSY6gW7CuOt" +
            "Z5fUgVgAX2rZ6fhG+CzoZktdrrbFH8Q8Reb1zgRXglBBcecXJ1xOB8XmpmUXYVpz" +
            "Lll4MgW1VoV1rvRDpfoX5Jykn5Ao3l6Mer5cuJq7Yk2DTkYS15w87jAnB3zBih+i" +
            "/aY3jWWr21/DWk19wAU3RxwGXJ9WIQErkeX/iOzH2nxIc/odCw==";

        #region CSR

        var validator = new YubikeyValidator([new X509Certificate2(Convert.FromBase64String(testCa))]);

        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10015);

        #endregion

        var result = new CertificateRequestValidationResult(dbRow);
        result = validator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        var policy = _policy;

        result = validator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.Null(yubikey);
        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.NTE_FAIL));
    }

    [Fact]
    public void Allows_when_more_than_one_attestation_Root()
    {
        var testCa =
            "MIID4TCCAkmgAwIBAgIQHgSMPLxvPotB6kiqNq2UkTANBgkqhkiG9w0BAQsFADAS" +
            "MRAwDgYDVQQDEwdURVNUIENBMCAXDTI1MDMxNjE1MTYzOFoYDzIxMjUwMzE2MTUz" +
            "NjM4WjASMRAwDgYDVQQDEwdURVNUIENBMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A" +
            "MIIBigKCAYEAwbgnqrr5klqk3UokMwuGZikXMinUS6yngsrGEN/5TEhpHGcJgVOo" +
            "uJmLZJBmnip4r4lV+qUJCJkv6hgcyheP3yZPS2SlzxCdgGZJYr0gIneYRkwLss2f" +
            "8ibngZskQ93QEXfhdQ8BQ8ivY8vhbFoTiUZP4JVfqiDlPsXTvGQSYL7cSbF+EW/N" +
            "LfEIeTtoBovl2hbyLq52W5a/SRfVU6S2BvpwO+OlPOWyiJxcereqIXLDzSihUItW" +
            "9vMB1ESmmtsh8+QlR5eZ/gVIJaW/uPb5u3fSejjNtuFy0xjb36e5wjfGJP1YrdEe" +
            "vsNF9cQ4jinlGiY/Gb8cPWTUQwGx2fLo4ehPF7pkB8iZZ+h9pxZGORYYTSFcL+o1" +
            "xFc1NGFAmCxHJG/8Osh+EKTiNbw/qztf3rIaXxJdtVMtCZi5yJ8y2rl52/6km+xy" +
            "sVnYxp4GNKm5fOcFMCsT7M/2c+/JkRWgRWhYXH85Lwn8b/wsNK1306g3TcJfX8lD" +
            "wmGwgwPTre6pAgMBAAGjMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUtfwW" +
            "OKLU32tltoOfzSgvq7UBJuMwDQYJKoZIhvcNAQELBQADggGBALq4j7hLBmbvHMAV" +
            "p0zEcdwUokiDzWYkLZ+TsQCsSIi5nyUSIm2C2zQFrWw3u3krKwwkNPGabAxw8V6p" +
            "GXfjUYWJ0Y7MJHrqM5qeATAFl/0TG0yhc53mdo9FdG7s7LStlZEUBd5ZxhSXm1mt" +
            "/UyGooz8emJKGbE0zXQdKlZM+5Bwdy5xiabsfBgAZm8/Hu0C47GEF3cKWxrU7KWc" +
            "Kp6mIT1ATnhSDPOSliWrinyw7Vvs8IxEbUo6BszGFe1CD7De2I72RT+/5acl31+3" +
            "xDSOz5C2i/0MIMxotLDxpgX51QmbMEP4FLvkwPpEebDIY9kqsPhFoOSY6gW7CuOt" +
            "Z5fUgVgAX2rZ6fhG+CzoZktdrrbFH8Q8Reb1zgRXglBBcecXJ1xOB8XmpmUXYVpz" +
            "Lll4MgW1VoV1rvRDpfoX5Jykn5Ao3l6Mer5cuJq7Yk2DTkYS15w87jAnB3zBih+i" +
            "/aY3jWWr21/DWk19wAU3RxwGXJ9WIQErkeX/iOzH2nxIc/odCw==";

        #region CSR

        var validator = new YubikeyValidator([
            new X509Certificate2(Convert.FromBase64String(testCa)), _yubikeyPivRootCaSerial263751
        ]);

        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10015);

        #endregion

        var result = new CertificateRequestValidationResult(dbRow);
        result = validator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        var policy = _policy;

        result = validator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);
        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Slot_Allow_policy_10017()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10017);

        // Allow if Slot is in an allow Policy
        var policy = _policy;
        policy.YubikeyPolicy[0].Slot = ["9a"];
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Slot_Deny_policy_10018()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10018);

        // Deny if Slot is in a deny Policy
        var policy = _policy;
        policy.YubikeyPolicy[0].Slot = ["9a"];
        policy.YubikeyPolicy[0].Action = PolicyAction.DENY;
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Validate_Slot_Missing_in_Allow_policy_10019()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10019);
        var policy = _policy;

        // Test if the slot is not in the only allow policy

        policy.YubikeyPolicy[0].Slot = ["9e"];
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.True(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Slot_Allow_if_Wrong_slot_is_denied_10020()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10020);

        // Allow if the Deny does not match this slot
        var policy = _policy;
        policy.YubikeyPolicy.Add(new YubikeyPolicy());
        policy.YubikeyPolicy[0].Action = PolicyAction.DENY;
        policy.YubikeyPolicy[0].Slot = ["9e"];
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        _output.WriteLine(policy.SaveToString());

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Slot_with_0x_10021()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10020);

        // Required slot 0x9a, which needs to match 9a
        var policy = _policy;
        policy.YubikeyPolicy[0].Slot = ["0x9a"];
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        _output.WriteLine(policy.SaveToString());

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Slot_incorrect_with_0x_10022()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10020);

        // Should not match the csr which is 9A
        var policy = _policy;
        policy.YubikeyPolicy[0].Slot = ["0x9e"];
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);
        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        _output.WriteLine(policy.SaveToString());

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Validate_YubikeyObject_to_human_readable_10023()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10023);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        PrintResult(result, yubikey);

        var serializedObject = yubikey.SaveToString();

        Assert.Contains($"<TouchPolicy>Never</TouchPolicy>", serializedObject);
        Assert.Contains($"<PinPolicy>Once</PinPolicy>", serializedObject);
        Assert.Contains($"<FormFactor>UsbAKeychain</FormFactor>", serializedObject);
        Assert.Contains($"<Slot>{yubikey.Slot}</Slot>", serializedObject);
        Assert.Contains($"<SerialNumber>{yubikey.SerialNumber}</SerialNumber>", serializedObject);
        Assert.Contains($"<FirmwareVersion>{yubikey.FirmwareVersionString}</FirmwareVersion>", serializedObject);
        Assert.Contains($"<KeyAlgorithm>{yubikey.KeyAlgorithm}</KeyAlgorithm>", serializedObject);
        Assert.Contains($"<KeyLength>{yubikey.KeyLength}</KeyLength>", serializedObject);
        Assert.Contains($"<Edition>Normal</Edition>", serializedObject);
        Assert.Contains(
            $"<AttestationCertificate>{Convert.ToBase64String(yubikey.AttestationCertificate.RawData)}</AttestationCertificate>",
            serializedObject);
        Assert.Contains(
            $"<IntermediateCertificate>{Convert.ToBase64String(yubikey.IntermediateCertificate.RawData)}</IntermediateCertificate>",
            serializedObject);
    }

    [Fact]
    public void Validate_all_configuration_options_10024()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10024);
        var policy = _policy;

        policy.YubikeyPolicy[0].KeyAlgorithmFamilies = [KeyAlgorithmFamily.RSA, KeyAlgorithmFamily.ECC];
        policy.YubikeyPolicy[0].MinimumFirmwareString = "0.0.0";
        policy.YubikeyPolicy[0].MaximumFirmwareString = "9.9.9";
        policy.YubikeyPolicy[0].FormFactor =
        [
            YubikeyFormFactor.USB_A_KEYCHAIN, YubikeyFormFactor.USB_C_KEYCHAIN, YubikeyFormFactor.USB_A_NANO,
            YubikeyFormFactor.USB_C_NANO, YubikeyFormFactor.USB_C_LIGHTNING, YubikeyFormFactor.USB_A_BIOMETRIC_KEYCHAIN,
            YubikeyFormFactor.USB_C_BIOMETRIC_KEYCHAIN
        ];
        policy.YubikeyPolicy[0].Edition = [YubikeyEdition.FIPS, YubikeyEdition.NORMAL, YubikeyEdition.CSPN];
        policy.YubikeyPolicy[0].Slot = ["9a", "9c", "9d", "9e"];
        policy.YubikeyPolicy[0].TouchPolicies =
            [YubikeyTouchPolicy.ALWAYS, YubikeyTouchPolicy.NEVER, YubikeyTouchPolicy.CACHED];
        policy.YubikeyPolicy[0].PinPolicies =
        [
            YubikeyPinPolicy.ONCE, YubikeyPinPolicy.NEVER, YubikeyPinPolicy.ALWAYS, YubikeyPinPolicy.MATCH_ONCE,
            YubikeyPinPolicy.MATCH_ALWAYS
        ];
        policy.YubikeyPolicy[0].Action = PolicyAction.ALLOW;

        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        PrintResult(result, yubikey);

        _output.WriteLine(policy.SaveToString());

        Assert.Contains("UsbANano", policy.SaveToString());
    }

    [Fact]
    public void Validate_Deny_Firmware_UpTo_5_2_7_10025()
    {
        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(
            Retrieve_CSR_from_Resource("TameMyCerts.Tests.Resources.YubiKeyValidator.5_2_7.pem"),
            CertCli.CR_IN_PKCS10, null, 10025);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].MaximumFirmwareString = "5.2.7";
        policy.YubikeyPolicy[0].Action = PolicyAction.DENY;

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Validate_Verify_Location_1_10026()
    {
        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(
            Retrieve_CSR_from_Resource("TameMyCerts.Tests.Resources.YubiKeyValidator.attestation_1.pem"),
            CertCli.CR_IN_PKCS10, null, 10026);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _ykValidator.GetYubikeyObject(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.0.0";
        policy.YubikeyPolicy[0].Action = PolicyAction.ALLOW;

        result = _ykValidator.VerifyRequest(result, policy, yubikey, dbRow);

        PrintResult(result, yubikey);

        Assert.False(result.DeniedForIssuance);
        Assert.Equal(YubikeyX509Extension.ATTESTATION_DEVICE,
            _listener.Events.First(x => x.EventId == 4209).Payload[1].ToString());
    }
}