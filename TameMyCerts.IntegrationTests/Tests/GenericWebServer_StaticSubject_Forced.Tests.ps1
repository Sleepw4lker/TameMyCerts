BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_StaticSubject_Forced"
}

Describe 'GenericWebServer_StaticSubject_Forced.Tests' {

    It 'Given a request doesnt contain it, a Subject RDN is supplemented' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local, O=Contoso Corp."
    }

    It 'Given a request does contain it, and the rule is set to enforce, a Subject RDN is supplemented' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local, O=Fabrikam Inc."
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local, O=Contoso Corp."
    }

}