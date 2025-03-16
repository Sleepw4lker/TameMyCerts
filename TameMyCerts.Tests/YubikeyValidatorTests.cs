using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
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
    private readonly CertificateContentValidator _cCvalidator = new();

    private readonly ETWLoggerListener _listener;

    private readonly ITestOutputHelper _output;
    private readonly CertificateRequestPolicy _policy;
    private readonly YubikeyValidator _yKvalidator;
    private readonly string _yubikey_valid_5_4_3_Always_Never_UsbAKeychain_9a_Normal_ECC_384_CSR;
    private readonly string _yubikey_valid_5_4_3_Once_Cached_UsbAKeychain_9a_FIPS_RSA_2048_CSR;
    private readonly CertificateDatabaseRow _yubikey_valid_5_4_3_Once_Cached_UsbAKeychain_9a_FIPS_RSA_2048_dbRow;
    private readonly string _yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR;
    private readonly CertificateDatabaseRow _yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_dbRow;
    private readonly string _yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR;
    private readonly CertificateDatabaseRow _yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_dbRow;

    private readonly X509Certificate2 yubikeyValidationCa = new(new byte[]
    {
        0x30, 0x82, 0x3, 0x17, 0x30, 0x82, 0x1, 0xFF, 0xA0, 0x3, 0x2, 0x1, 0x2, 0x2, 0x3, 0x4, 0x6, 0x47, 0x30, 0xD,
        0x6, 0x9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0xD, 0x1, 0x1, 0xB, 0x5, 0x0, 0x30, 0x2B, 0x31, 0x29, 0x30, 0x27, 0x6,
        0x3, 0x55, 0x4, 0x3, 0xC, 0x20, 0x59, 0x75, 0x62, 0x69, 0x63, 0x6F, 0x20, 0x50, 0x49, 0x56, 0x20, 0x52, 0x6F,
        0x6F, 0x74, 0x20, 0x43, 0x41, 0x20, 0x53, 0x65, 0x72, 0x69, 0x61, 0x6C, 0x20, 0x32, 0x36, 0x33, 0x37, 0x35,
        0x31, 0x30, 0x20, 0x17, 0xD, 0x31, 0x36, 0x30, 0x33, 0x31, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x18,
        0xF, 0x32, 0x30, 0x35, 0x32, 0x30, 0x34, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x2B, 0x31,
        0x29, 0x30, 0x27, 0x6, 0x3, 0x55, 0x4, 0x3, 0xC, 0x20, 0x59, 0x75, 0x62, 0x69, 0x63, 0x6F, 0x20, 0x50, 0x49,
        0x56, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x20, 0x53, 0x65, 0x72, 0x69, 0x61, 0x6C, 0x20, 0x32,
        0x36, 0x33, 0x37, 0x35, 0x31, 0x30, 0x82, 0x1, 0x22, 0x30, 0xD, 0x6, 0x9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0xD,
        0x1, 0x1, 0x1, 0x5, 0x0, 0x3, 0x82, 0x1, 0xF, 0x0, 0x30, 0x82, 0x1, 0xA, 0x2, 0x82, 0x1, 0x1, 0x0, 0xC3, 0x76,
        0x70, 0xC4, 0xCD, 0x47, 0xA6, 0x2, 0x75, 0xC4, 0xC5, 0x47, 0x1B, 0x8F, 0xCB, 0x7D, 0x4F, 0x69, 0xB4, 0x67, 0xE6,
        0x6E, 0xA9, 0x27, 0xE9, 0xD2, 0x13, 0x41, 0xD1, 0x5A, 0x9A, 0x1A, 0x33, 0xC7, 0xDC, 0xF3, 0x1, 0xC2, 0xF9, 0x39,
        0x9B, 0xF7, 0xC8, 0xE6, 0x36, 0xF8, 0x56, 0x34, 0x4D, 0x84, 0x8A, 0x55, 0x3C, 0xE6, 0xE6, 0xA, 0x7C, 0x41, 0x4F,
        0xF5, 0xDE, 0x90, 0xD8, 0x69, 0xB2, 0xB6, 0xA0, 0x67, 0xC5, 0x9B, 0x0, 0x6B, 0x72, 0xAA, 0x66, 0x20, 0x82, 0xC7,
        0x62, 0xF0, 0x43, 0x88, 0x98, 0x10, 0xE6, 0xF5, 0x96, 0x58, 0x28, 0xB5, 0x5A, 0xFF, 0xC2, 0x11, 0x29, 0x75,
        0x53, 0xAA, 0x8E, 0x85, 0x34, 0x3F, 0x97, 0xB5, 0x8F, 0x5C, 0xBB, 0x39, 0xFC, 0xE, 0xBE, 0x4C, 0xBF, 0xF8, 0x5,
        0xC8, 0x37, 0xFF, 0x57, 0xA7, 0x45, 0x45, 0x95, 0x84, 0x64, 0xDA, 0xD4, 0x3D, 0x19, 0xC7, 0x58, 0x28, 0x39,
        0xAA, 0x53, 0xE7, 0x5B, 0xF6, 0x22, 0xB0, 0xA4, 0xC, 0xE2, 0x77, 0x8A, 0x7, 0x5, 0x52, 0xC8, 0x86, 0x60, 0xF7,
        0xA6, 0xF9, 0x16, 0x69, 0x10, 0x36, 0x1F, 0x70, 0xC0, 0xF6, 0xDE, 0xC7, 0xFC, 0x73, 0x6A, 0xE6, 0xFD, 0xCE,
        0x88, 0xED, 0x63, 0xC8, 0xB6, 0x5E, 0x2A, 0xA6, 0x68, 0x31, 0xB3, 0xCE, 0x6E, 0xBC, 0x6A, 0xE, 0xF, 0xBD, 0x7C,
        0xE7, 0x52, 0x87, 0x38, 0x1F, 0xC0, 0x2A, 0xA0, 0x4F, 0x75, 0xD5, 0x99, 0x37, 0xA2, 0xC2, 0xF0, 0x52, 0x4D,
        0xCB, 0x72, 0x8B, 0xD9, 0x87, 0x41, 0xF6, 0x1D, 0xD8, 0x3C, 0x24, 0x6A, 0xAC, 0x51, 0x9C, 0xB6, 0xCD, 0x57,
        0x22, 0xBD, 0xCE, 0x5F, 0x83, 0xCE, 0x34, 0x86, 0xA7, 0xD2, 0x21, 0x54, 0xF8, 0x95, 0xB4, 0x67, 0xAD, 0x5F,
        0x4D, 0x9D, 0xC6, 0x14, 0x27, 0x19, 0x2E, 0xCA, 0xE8, 0x13, 0xB4, 0x41, 0xEF, 0x2, 0x3, 0x1, 0x0, 0x1, 0xA3,
        0x42, 0x30, 0x40, 0x30, 0x1D, 0x6, 0x3, 0x55, 0x1D, 0xE, 0x4, 0x16, 0x4, 0x14, 0xCA, 0x5F, 0xCA, 0xF2, 0xC4,
        0xA2, 0x31, 0x9C, 0xE9, 0x22, 0x5F, 0xF1, 0xEC, 0xF4, 0xD5, 0xDF, 0x2, 0xBF, 0x83, 0xBF, 0x30, 0xF, 0x6, 0x3,
        0x55, 0x1D, 0x13, 0x4, 0x8, 0x30, 0x6, 0x1, 0x1, 0xFF, 0x2, 0x1, 0x1, 0x30, 0xE, 0x6, 0x3, 0x55, 0x1D, 0xF, 0x1,
        0x1, 0xFF, 0x4, 0x4, 0x3, 0x2, 0x1, 0x6, 0x30, 0xD, 0x6, 0x9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0xD, 0x1, 0x1, 0xB,
        0x5, 0x0, 0x3, 0x82, 0x1, 0x1, 0x0, 0x5C, 0xEC, 0x88, 0x7C, 0x5, 0xCD, 0x5F, 0x90, 0x2F, 0x85, 0xC8, 0xDD, 0x5F,
        0x86, 0x35, 0xA2, 0xA0, 0x10, 0x8C, 0xAF, 0x7B, 0xE3, 0x9D, 0xE8, 0x7B, 0x30, 0xB6, 0xC0, 0xEA, 0x44, 0xA8,
        0xC9, 0x61, 0x7B, 0xD0, 0xDD, 0xEC, 0x5E, 0x16, 0xD7, 0xBD, 0x3E, 0x1E, 0x46, 0x1D, 0x21, 0xBF, 0x1A, 0xAF,
        0x31, 0x93, 0x63, 0x3D, 0x4F, 0xD5, 0x95, 0x19, 0xFA, 0x80, 0xB5, 0x6D, 0xA0, 0x48, 0xA4, 0xC, 0xBA, 0xD8, 0x15,
        0x73, 0x7A, 0x1E, 0x1E, 0x96, 0x9B, 0x2C, 0xB5, 0x19, 0x39, 0xEC, 0xA6, 0x73, 0xAF, 0x32, 0xFC, 0xF6, 0x94,
        0xB2, 0xAE, 0xCA, 0x6F, 0x4A, 0x61, 0xD6, 0xB, 0xE, 0x9, 0xE3, 0xDC, 0x17, 0x80, 0xBF, 0x32, 0x21, 0x57,
        0x3C, 0xD8, 0x49, 0xE5, 0x3B, 0xEF, 0xF0, 0xAE, 0xA6, 0x87, 0xE3, 0xD3, 0xDD, 0xCE, 0xB8, 0xB, 0x30, 0x5B, 0x48,
        0xD8, 0xBD, 0x7B, 0x6, 0x4F, 0x28, 0xB1, 0xE8, 0x1D, 0xDD, 0x6D, 0x6E, 0x72, 0x5A, 0xFC, 0x92, 0xF7, 0x33, 0x57,
        0x6A, 0xA1, 0x9A, 0x52, 0x63, 0xF7, 0x53, 0xDF, 0xDB, 0xE8, 0x39, 0x47, 0x74, 0x3A, 0x20, 0x30, 0xBB, 0xB7,
        0x54, 0xBA, 0x41, 0x7, 0xD6, 0xE6, 0xE5, 0xB8, 0xDA, 0x29, 0x65, 0x89, 0x62, 0x5, 0xA5, 0xB4, 0x25, 0x60, 0x51,
        0xB1, 0x6A, 0x16, 0xAC, 0xA2, 0xE3, 0xE2, 0x44, 0xD3, 0x5E, 0x1C, 0x4A, 0x4, 0x79, 0xEC, 0x97, 0x2E, 0xDD, 0xD6,
        0x62, 0x7A, 0x10, 0x7A, 0x52, 0xD0, 0xF, 0x81, 0xA7, 0x7D, 0x2F, 0x97, 0xD, 0xBE, 0xE6, 0xBF, 0x21, 0x64, 0x66,
        0x9B, 0xE0, 0xD, 0xCB, 0x73, 0xB6, 0x2C, 0x7F, 0xBE, 0x3F, 0x29, 0x7C, 0x49, 0x11, 0x33, 0x53, 0xCA, 0x27, 0x6C,
        0x1B, 0x23, 0x32, 0xF, 0x50, 0xE, 0x24, 0x9F, 0xE6, 0x82, 0x4B, 0x2A, 0xF7, 0x7F, 0x45, 0xE9, 0xFE, 0xCC, 0x66,
        0x3B
    });


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
            YubikeyPolicy = new List<YubikeyPolicy>
            {
                new()
            }
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

        _yKvalidator = new YubikeyValidator(new X509Certificate2Collection { yubikeyValidationCa });
    }

    internal void PrintResult(CertificateRequestValidationResult result)
    {
        _output.WriteLine("0x{0:X} ({0}) {1}.", result.StatusCode,
            new Win32Exception(result.StatusCode).Message);
        _output.WriteLine(string.Join("\n", result.Description));
    }

    [Fact]
    public void Extract_Genuine_Yubikey_Attestation_10001()
    {
        _listener.ClearEvents();
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10001);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        Assert.True(yubikey.TouchPolicy == YubikeyTouchPolicy.Never);
        Assert.True(yubikey.PinPolicy == YubikeyPinPolicy.Once);
        Assert.True(yubikey.FirmwareVersion == new Version(5, 4, 3));
        Assert.True(yubikey.FormFactor == YubikeyFormFactor.UsbAKeychain);
        Assert.True(yubikey.Slot == "9a");

        // Validate that we get a debug message with the attestation OID information
        Assert.Contains(4209, _listener.Events.Select(e => e.EventId));
        // Validate that the 4209 says that the attestation comes from the faulty PIVTOOL OID
        Assert.Equal(YubikeyX509Extensions.ATTESTATION_DEVICE_PIVTOOL,
            _listener.Events.First(x => x.EventId == 4209).Payload[1].ToString());

        PrintResult(result);
    }

    [Fact]
    public void Validate_Policy_MinimumFirmware_5_7_1_should_Reject_10002()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10002);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.7.1";

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10002);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Policy_MinimumFirmware_5_7_1_should_Allow_10003()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10003);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.7.1";

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10003);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_PIN_Policy_Once_should_Allow_10004()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10004);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].PinPolicies.Add(YubikeyPinPolicy.Once);

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10004);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_PIN_Policy_Deny_Never_should_Allow_10005()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10005);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].PinPolicies.Add(YubikeyPinPolicy.Never);
        policy.YubikeyPolicy[0].Action = YubikeyPolicyAction.Deny;

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10005);
        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_PIN_Policy_Deny_Once_should_Deny_10006()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10006);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].PinPolicies.Add(YubikeyPinPolicy.Once);
        policy.YubikeyPolicy[0].Action = YubikeyPolicyAction.Deny;

        _listener.ClearEvents();

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10006);

        PrintResult(result);

        Assert.Single(_listener.Events); // Ensure one event was logged
        Assert.Equal(4201, _listener.Events[0].EventId);
        Assert.True(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_FIPS_Edition_Should_Deny_10007()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10007);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);
        var policy = _policy;
        policy.YubikeyPolicy[0].Edition.Add(YubikeyEdition.FIPS);

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10007);
        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_FIPS_Edition_Should_Allow_10008()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Cached_UsbAKeychain_9a_FIPS_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10008);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].Edition.Add(YubikeyEdition.FIPS);

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10008);
        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_PIN_Policy_VerifyAll_10009()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10009);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].PinPolicies.Add(YubikeyPinPolicy.Once);
        policy.YubikeyPolicy[0].TouchPolicies.Add(YubikeyTouchPolicy.Never);
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.4.0";
        policy.YubikeyPolicy[0].MaximumFirmwareString = "5.7.0";
        policy.YubikeyPolicy[0].Formfactor.Add(YubikeyFormFactor.UsbAKeychain);
        policy.YubikeyPolicy[0].Edition.Add(YubikeyEdition.Normal);
        policy.YubikeyPolicy[0].KeyAlgorithmFamilies.Add(KeyAlgorithmFamily.RSA);

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10009);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Touch_Policy_Allow_Never_should_Allow_10010()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10010);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].TouchPolicies.Add(YubikeyTouchPolicy.Never);

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10010);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Touch_Policy_Deny_Never_should_Deny_10011()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10011);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].TouchPolicies.Add(YubikeyTouchPolicy.Never);
        policy.YubikeyPolicy[0].Action = YubikeyPolicyAction.Deny;

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10011);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Touch_Policy_Allowed_Always_should_Deny_10012()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10012);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].TouchPolicies.Add(YubikeyTouchPolicy.Always);

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10012);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Require_Firmware_Above_5_7_1_to_allow_ECC_should_allow_10013()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10013);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].KeyAlgorithmFamilies.Add(KeyAlgorithmFamily.ECC);
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.7.1";

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, 10013);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Require_Firmware_Above_5_7_1_to_allow_ECC_should_deny_10016()
    {
        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Always_Never_UsbAKeychain_9a_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10016);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].KeyAlgorithmFamilies.Add(KeyAlgorithmFamily.ECC);
        policy.YubikeyPolicy[0].MinimumFirmwareString = "5.7.1";

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, dbRow.RequestID);

        PrintResult(result);

        Assert.Contains(4203, _listener.Events.Select(e => e.EventId));
        Assert.True(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Deny_Firmware_Below_5_6_9_with_ECC_should_deny_10017()
    {
        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Always_Never_UsbAKeychain_9a_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10017);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].KeyAlgorithmFamilies.Add(KeyAlgorithmFamily.ECC);
        policy.YubikeyPolicy[0].MaximumFirmwareString = "5.6.9";
        policy.YubikeyPolicy[0].Action = YubikeyPolicyAction.Deny;

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, dbRow.RequestID);

        PrintResult(result);

        Assert.Contains(4201, _listener.Events.Select(e => e.EventId));
        Assert.True(result.DeniedForIssuance);
    }

    [Fact]
    public void Validate_Deny_Firmware_Below_5_6_9_with_ECC_should_allow_10018()
    {
        _listener.ClearEvents();

        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_7_1_Always_Always_UsbCKeychain_9c_Normal_ECC_384_CSR,
            CertCli.CR_IN_PKCS10, null, 10018);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);

        var policy = _policy;
        policy.YubikeyPolicy[0].KeyAlgorithmFamilies.Add(KeyAlgorithmFamily.ECC);
        policy.YubikeyPolicy[0].MaximumFirmwareString = "5.6.9";
        policy.YubikeyPolicy[0].Action = YubikeyPolicyAction.Deny;

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, dbRow.RequestID);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
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
        result = _yKvalidator.ExtractAttestation(result, policy, dbRow, out var yubikey);
        result = _cCvalidator.VerifyRequest(result, policy, dbRow, null, _caConfig, yubikey);

        PrintResult(result);

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
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikeyInfo);

        var policy = _policy;
        policy.OutboundSubject.Add(new OutboundSubjectRule
            {
                Field = RdnTypes.CommonName,
                Value = "{yk:slot}",
                Mandatory = true,
                Force = true
            }
        );

        result = _yKvalidator.VerifyRequest(result, policy, yubikeyInfo, dbRow.RequestID);
        result = _cCvalidator.VerifyRequest(result, policy,
            _yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_dbRow, null, _caConfig, yubikeyInfo);

        PrintResult(result);

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
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikey);
        var policy = _policy;

        result = _yKvalidator.VerifyRequest(result, policy, yubikey, dbRow.RequestID);

        PrintResult(result);
        Assert.Contains(4207, _listener.Events.Select(e => e.EventId));
        Assert.True(result.DeniedForIssuance);
    }


    [Fact]
    public void Include_the_AttestationData_in_Certificate_10016()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10014);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikeyInfo);

        var policy = _policy;
        policy.YubikeyPolicy[0].IncludeAttestationInCertificate = true;

        result = _yKvalidator.VerifyRequest(result, policy, yubikeyInfo, dbRow.RequestID);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.CertificateExtensions.ContainsKey(YubikeyX509Extensions.ATTESTATION_DEVICE));
    }

    [Fact]
    public void Validate_Slot_Allow_policy_10017()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10017);

        // Allow if Slot is in an allow Policy
        var policy = _policy;
        policy.YubikeyPolicy[0].Slot = new List<string> { "9a" };
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikeyInfo);
        result = _yKvalidator.VerifyRequest(result, policy, yubikeyInfo, dbRow.RequestID);

        PrintResult(result);

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
        policy.YubikeyPolicy[0].Action = YubikeyPolicyAction.Deny;
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikeyInfo);
        result = _yKvalidator.VerifyRequest(result, policy, yubikeyInfo, dbRow.RequestID);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
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
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikeyInfo);
        result = _yKvalidator.VerifyRequest(result, policy, yubikeyInfo, dbRow.RequestID);
        Assert.True(result.DeniedForIssuance);

        PrintResult(result);
    }

    [Fact]
    public void Validate_Slot_Allow_if_Wrong_slot_is_denied_10020()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10020);

        // Allow if the Deny does not match this slot
        var policy = _policy;
        policy.YubikeyPolicy.Add(new YubikeyPolicy());
        policy.YubikeyPolicy[0].Action = YubikeyPolicyAction.Deny;
        policy.YubikeyPolicy[0].Slot = new List<string> { "9e" };
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikeyInfo);
        result = _yKvalidator.VerifyRequest(result, policy, yubikeyInfo, dbRow.RequestID);
        Assert.False(result.DeniedForIssuance);
        PrintResult(result);

        _output.WriteLine(policy.SaveToString());
    }

    [Fact]
    public void Validate_Slot_with_0x_10021()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10020);

        // Required slot 0x9a, which needs to match 9a
        var policy = _policy;
        policy.YubikeyPolicy[0].Slot = new List<string> { "0x9a" };
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikeyInfo);
        result = _yKvalidator.VerifyRequest(result, policy, yubikeyInfo, dbRow.RequestID);
        Assert.False(result.DeniedForIssuance);
        PrintResult(result);

        _output.WriteLine(policy.SaveToString());
    }

    [Fact]
    public void Validate_Slot_incorrect_with_0x_10022()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10020);

        // Should not match the csr which is 9A
        var policy = _policy;
        policy.YubikeyPolicy[0].Slot = new List<string> { "0x9e" };
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikeyInfo);
        result = _yKvalidator.VerifyRequest(result, policy, yubikeyInfo, dbRow.RequestID);
        Assert.True(result.DeniedForIssuance);
        PrintResult(result);

        _output.WriteLine(policy.SaveToString());
    }

    [Fact]
    public void Validate_YubiKeyObject_to_Human_readable_10023()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10023);
        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikeyInfo);

        PrintResult(result);

        _output.WriteLine(yubikeyInfo.SaveToString());

        Assert.Contains("19661687", yubikeyInfo.SaveToString());
    }

    [Fact]
    public void Validate_all_configuration_options_10024()
    {
        var dbRow = new CertificateDatabaseRow(_yubikey_valid_5_4_3_Once_Never_UsbAKeychain_9a_Normal_RSA_2048_CSR,
            CertCli.CR_IN_PKCS10, null, 10024);
        var policy = _policy;

        policy.YubikeyPolicy[0].KeyAlgorithmFamilies = new List<KeyAlgorithmFamily>
            { KeyAlgorithmFamily.RSA, KeyAlgorithmFamily.ECC };
        policy.YubikeyPolicy[0].MinimumFirmwareString = "0.0.0";
        policy.YubikeyPolicy[0].MaximumFirmwareString = "9.9.9";
        policy.YubikeyPolicy[0].Formfactor = new List<YubikeyFormFactor>
        {
            YubikeyFormFactor.UsbAKeychain, YubikeyFormFactor.UsbCKeychain, YubikeyFormFactor.UsbANano,
            YubikeyFormFactor.UsbCNano, YubikeyFormFactor.UsbCLightning, YubikeyFormFactor.UsbABiometricKeychain,
            YubikeyFormFactor.UsbCBiometricKeychain
        };
        policy.YubikeyPolicy[0].Edition = new List<YubikeyEdition>
            { YubikeyEdition.FIPS, YubikeyEdition.Normal, YubikeyEdition.CSPN };
        policy.YubikeyPolicy[0].Slot = new List<string> { "9a", "9c", "9d", "9e" };
        policy.YubikeyPolicy[0].TouchPolicies = new List<YubikeyTouchPolicy>
            { YubikeyTouchPolicy.Always, YubikeyTouchPolicy.Never, YubikeyTouchPolicy.Cached };
        policy.YubikeyPolicy[0].PinPolicies = new List<YubikeyPinPolicy>
        {
            YubikeyPinPolicy.Once, YubikeyPinPolicy.Never, YubikeyPinPolicy.Always, YubikeyPinPolicy.MatchOnce,
            YubikeyPinPolicy.MatchAlways
        };
        policy.YubikeyPolicy[0].Action = YubikeyPolicyAction.Allow;

        var result = new CertificateRequestValidationResult(dbRow);
        result = _yKvalidator.ExtractAttestation(result, _policy, dbRow, out var yubikeyInfo);

        PrintResult(result);

        _output.WriteLine(policy.SaveToString());

        Assert.Contains("UsbANano", policy.SaveToString());
    }
}