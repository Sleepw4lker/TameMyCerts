BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Online_Yubikey"
}

Describe 'User_Online_Yubikey.Tests' {

    It 'Given YubiKey Policy is enabled and a request contains a valid attestation, a certificate is issued' {

        $Csr =  "MIIIxDCCB6wCAQAwHDEaMBgGA1UEAwwRVGFtZU15Q2VydHNfNS43LjIwggEiMA0G" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8PsNNUt67rgq4+EGGnBU46XiiXv4g" +
                "ADdAhOB8IQp1eZ+7Dq8JOQ9XDjjBObPj7TnEzxS+PSpXTmwV46FA4gykcVj+tRhT" +
                "zMyaMWDrgdBoJ4sRRf+9GunayxSlPD4ConoLnDxFZYSiz2fyoGlWAljiFTbGM8Lh" +
                "TJ0UQ7702YdncIYhxGhIL9EZzOfawx27Hf+JocSrPdkriHVjQ0stv2hhtfv/ONAO" +
                "3uzT4lTsrRhYP7INV449yR3KPzEdjA3J8K9D7CllIkWpC3Zt75lMmVgla+684pXT" +
                "AhIKuh0Z3gKKyUAsFAoMVvpTbE6E+WX0mOX8YBdNb93gHMyyDRlY9lQDAgMBAAGg" +
                "ggZhMIIGXQYJKoZIhvcNAQkOMYIGTjCCBkowggM0BgorBgEEAYLECgMLBIIDJDCC" +
                "AyAwggIIoAMCAQICEAG2+elXHedw3FPc5lbltMIwDQYJKoZIhvcNAQELBQAwITEf" +
                "MB0GA1UEAwwWWXViaWNvIFBJViBBdHRlc3RhdGlvbjAgFw0xNjAzMTQwMDAwMDBa" +
                "GA8yMDUyMDQxNzAwMDAwMFowJTEjMCEGA1UEAwwaWXViaUtleSBQSVYgQXR0ZXN0" +
                "YXRpb24gOWEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8PsNNUt67" +
                "rgq4+EGGnBU46XiiXv4gADdAhOB8IQp1eZ+7Dq8JOQ9XDjjBObPj7TnEzxS+PSpX" +
                "TmwV46FA4gykcVj+tRhTzMyaMWDrgdBoJ4sRRf+9GunayxSlPD4ConoLnDxFZYSi" +
                "z2fyoGlWAljiFTbGM8LhTJ0UQ7702YdncIYhxGhIL9EZzOfawx27Hf+JocSrPdkr" +
                "iHVjQ0stv2hhtfv/ONAO3uzT4lTsrRhYP7INV449yR3KPzEdjA3J8K9D7CllIkWp" +
                "C3Zt75lMmVgla+684pXTAhIKuh0Z3gKKyUAsFAoMVvpTbE6E+WX0mOX8YBdNb93g" +
                "HMyyDRlY9lQDAgMBAAGjTjBMMBEGCisGAQQBgsQKAwMEAwUHAjAUBgorBgEEAYLE" +
                "CgMHBAYCBAHJxzQwEAYKKwYBBAGCxAoDCAQCAgEwDwYKKwYBBAGCxAoDCQQBBzAN" +
                "BgkqhkiG9w0BAQsFAAOCAQEAMelAlg5eeQYHwLZfcSZOPoCH2m7BMe4TXEyLIOeY" +
                "TvtRT7QfShJ3GUUq7uOuqHfIlDjfJ3myxmGZHYXQ6JI/MFRA0BYYNUzW4dYKyyOf" +
                "Lcbz057xwA2ft7Xpva7Hg931xOfY4wuFlOZMDuMxupVYHVBnimTQBzStBpzYd/Uj" +
                "4f/49DWFtlfaYCLVjAoLxrvLRq+FD7CjAFFTRMQ8eE2kJiFKtimpfZuWauTe7y3Y" +
                "5GqZFmYlVVZh/PwqUo91CfCjK2aAJksYhisfsnIY+eoKSzzQGNdlm36XER9XJenX" +
                "8fT8xPN5COLSAwVoNCDWjmXvjaVDTKRmgTxSR/rGhu9YAzCCAw4GCisGAQQBgsQK" +
                "AwIEggL+MIIC+jCCAeKgAwIBAgIJAMpbDtY+hB0HMA0GCSqGSIb3DQEBCwUAMCsx" +
                "KTAnBgNVBAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2" +
                "MDMxNDAwMDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28g" +
                "UElWIEF0dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" +
                "uwa0Ew85h+5AZ6bCxIGAKB6T8LSUk+AvezISSr6bglRP+GkAmNy1sHkjpBtlmS3H" +
                "VwRTSnL6+NuG7tmV64uVMhCr0RmLRwmAnk4CRr+CLLa1ZwkBeDgoYAhs+/kS8XhL" +
                "/cYCtj9ihLq9li4pfX4m8OP+NdvSEczecA8sXvi4rAHEW4wPh1wYvj+B2fHus7Q/" +
                "oOWP8DYblnkpeXl70qB7w4tceXa+l7GQqnJvRBlCGrh+H1wjTVTTVPC8JuKkAlwf" +
                "IMb/2AQvNY01/bu8aBzHhc1xdrvcCO3jJxAR6X8Yip8I7YuGnsXAbuQOyyZNM5+9" +
                "p5O0pOKYRI1aVWTQyUsZmQIDAQABoykwJzARBgorBgEEAYLECgMDBAMFBwIwEgYD" +
                "VR0TAQH/BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAdPC7v6yKyurYYOKc" +
                "6EQ/qSCXiNwqU63NYkfB5rPncPs2aspBQ+S56RwHdRpebn3K91j17U3mGtFF5J75" +
                "N1Kgqlc/o4JQE1A1yWI1RF9rMPT3g2mwDJ+OmzNkAyqBeYgQa4lCFUxtP9MBozL6" +
                "qsU5vChrLY1RsQ3FVuoa4ZC8zsVheDCGKuN+67KgPD3logr/AwdgU3BnOrWXHFo4" +
                "WuDWPAhl8qKeVSxorklqETbKwZcRdMrgRXPJys3htlvrxYzMl++DpQ3k7MyPHevW" +
                "YSOASMCat2POJ5XKqwh2OSDD9Lv7fhtzzao3xIaIZHRs22TKDMfEbAhdzKkId8jN" +
                "8Z5PhTANBgkqhkiG9w0BAQsFAAOCAQEAWl/6KR9LtjZkXUbAE3Dq1W3cZtirauTv" +
                "pSRPyMKFIxN2r7xnano+KgcBsETl+zUg/VemfeWj3dHxPR2YwGo2zMNaxDjCycLT" +
                "bmazQ6uBRSxHCEcfqHRb8JEx6+utmSNgfZ4yLmjppXMmlro14iVCiXZjkUFXZ5J6" +
                "ERvx7KNx/wjblVYpm3MlDJODEncniSWncEeijlEADZ5v2jJPQ/wNjF6oWhmXwh8a" +
                "ggcGh2bCoTp849O3apMTZ5Q+SbLGIueAPRpqfn0POue/tJ1yAaaBa0N9A61cAV0i" +
                "m9ZF6Y/25/EBswRWtV+0WsWcGmTtvW9GQcK95FAMMqnz0wZ0oVDSoQ=="

        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given YubiKey Policy is enabled and a request contains no valid attestation, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=test"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }

}