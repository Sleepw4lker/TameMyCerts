BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_StaticSubject"
}

Describe 'GenericWebServer_StaticSubject.Tests' {

    It 'Given a request doesnt contain it, a Subject RDN is supplemented' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tmctests.internal, O=Contoso Corp."
    }

    It 'Given a request does contain it, no Subject RDN is supplemented' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal, O=Fabrikam Inc."
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tmctests.internal, O=Fabrikam Inc."
    }

}