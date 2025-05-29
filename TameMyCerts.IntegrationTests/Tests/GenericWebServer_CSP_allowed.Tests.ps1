BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_CSP_allowed"
}

Describe 'GenericWebServer_CSP_allowed.Tests' {

    It 'Given a request is compliant, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal" -Ksp "Microsoft Software Key Storage Provider"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tmctests.internal"
    }

    It 'Given a request is not compliant, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal" -Ksp "Microsoft Enhanced RSA and AES Cryptographic Provider"
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED

        Test-AppEvent -Date $Now -Message "*Cryptographic provider ""Microsoft Enhanced RSA and AES Cryptographic Provider"" used to create the certificate request is not on the list of allowed providers." | Should -Be $True
    }

}