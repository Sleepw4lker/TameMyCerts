BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "Computer_Online_ECDSA"
}

Describe 'Computer_Online_ECDSA.Tests' {

    It 'Given the key is compliant, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDSA_P384
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given the key is not compliant, a certificate is issued (key is too small)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDSA_P256
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH

        Test-AppEvent -Date $Now -Message "*Key length of 256 Bits is less than the required minimum length of 384 Bits." | Should -Be $True
    }

    It 'Given the key is not compliant, no certificate is issued (key is DSA)' {

        $RequestFileName = "$($env:temp)\$((New-Guid).Guid).req"
        [void](& certreq.exe -new "$PSScriptRoot\Computer_Online_DSA.inf" $RequestFileName)
        $Csr = Get-Content -Path $RequestFileName -raw

        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH

        Test-AppEvent -Date $Now -Message "*The certificate request does not use a ECC key pair as required by the certificate template, but a DSA key pair." | Should -Be $True
    }

    It 'Given the key is not compliant, no certificate is issued (key is RSA)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm RSA
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH

        Test-AppEvent -Date $Now -Message "*The certificate request does not use a ECC key pair as required by the certificate template, but a RSA key pair." | Should -Be $True
    }

}