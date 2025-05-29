BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "Computer_Online_CDP-AIA-OCSP"
}

Describe 'Computer_Online_CDP-AIA-OCSP.Tests' {

    It 'Given custom CDP, AIA or OCSP extensions are configured, they are written into the issued certificate' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDSA_P256
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $([Convert]::ToBase64String(($Result.Certificate.Extensions | Where-Object { $_.Oid.Value.Equals($Oid.XCN_OID_CRL_DIST_POINTS) }).RawData)) | 
            Should -Be "MDgwNqA0oDKGMGh0dHA6Ly9jcmwudGFtZW15Y2VydHMtY3VzdG9tLmNvbS9MYWJSb290Q0ExLmNybA=="
        $([Convert]::ToBase64String(($Result.Certificate.Extensions | Where-Object { $_.Oid.Value.Equals($Oid.XCN_OID_AUTHORITY_INFO_ACCESS) }).RawData)) |
            Should -Be "MGswOAYIKwYBBQUHMAKGLGh0dHA6Ly90YW1lbXljZXJ0cy1jdXN0b20uY29tL0xhYlJvb3RDQTEuY3J0MC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC50YW1lbXljZXJ0cy1jdXN0b20uY29tLw=="
    }

}