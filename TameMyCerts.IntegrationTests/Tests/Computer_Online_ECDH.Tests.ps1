BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "Computer_Online_ECDH"
}

Describe 'Computer_Online_ECDH.Tests' {

    It 'Given the key is compliant, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDH_P256
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given the key is not compliant, no certificate is issued (key is RSA)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm RSA
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH

        Test-AppEvent -Date $Now -Message "*The certificate request does not use a ECC key pair as required by the certificate template, but a RSA key pair." | Should -Be $True
    }

    <# DSA and ECDSA do not need to be tested as there are incompatible and will throw CERT_E_WRONG_USAGE by the default policy module #>

}