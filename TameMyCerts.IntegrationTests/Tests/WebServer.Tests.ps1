BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "WebServer"
}

Describe 'WebServer.Tests' {

    It 'Given a request against a V1 template is compliant, a certificate is issued' {

        $Identity = "this-is-a-test"
        $Csr = New-CertificateRequest -Subject "CN=$Identity"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=$Identity"
    }

    It 'Given a request against a V1 template is not compliant, no certificate is issued' {

        $Identity = "this-is-another-test"
        $Csr = New-CertificateRequest -Subject "CN=$Identity"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }
}