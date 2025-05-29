BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_emptyPolicy"
}

Describe 'GenericWebServer_emptyPolicy.Tests' {

    It 'Given a request is not compliant, no certificate is issued (RDN type not defined)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal" -KeyLength 2048
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME

        Test-AppEvent -Date $Now -Message "*The commonName field is not allowed." | Should -Be $True
    }
}