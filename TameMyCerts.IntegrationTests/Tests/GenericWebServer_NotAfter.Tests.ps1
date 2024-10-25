BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_NotAfter"
}

Describe 'GenericWebServer_NotAfter.Tests' {

    It 'Given an ExpirationDate is configured, a certificate is issued with correct NotAfter date' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
        $Result.Certificate.NotAfter | Should -Be (Get-Date -Date "2060-12-31 23:59:59Z")
    }

}