BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_StaticSubjectAlternativeName_Forced"
}

Describe 'GenericWebServer_StaticSubjectAlternativeName_Forced.Tests' {

    It 'Given a request doesnt contain it, a SAN is supplemented' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS

        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "rfc822Name=info@adcslabor.de"
    }

    It 'Given a request does contain it, a SAN is supplemented' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal" -RFC822Name "support@adcslabor.de"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS

        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "rfc822Name=support@adcslabor.de"
        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "rfc822Name=info@adcslabor.de"
    }

}