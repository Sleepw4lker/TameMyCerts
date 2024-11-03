BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "Computer_Online_DSA"
}

Describe 'Computer_Online_DSA.Tests' {

    It 'Given the key is compliant, a certificate is issued' {

        $RequestFileName = "$($env:temp)\$((New-Guid).Guid).req"
        [void](& certreq.exe -new "$PSScriptRoot\$($CertificateTemplate).inf" $RequestFileName)
        $Csr = Get-Content -Path $RequestFileName -raw

        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given the key is not compliant, no certificate is issued (RSA)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm RSA
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH

        Test-AppEvent -Date $Now -Message "*The certificate request does not use a DSA key pair as required by the certificate template, but a RSA key pair." | Should -Be $True
    }

    It 'Given the key is not compliant, no certificate is issued (ECDSA)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDSA_P256
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH

        Test-AppEvent -Date $Now -Message "*The certificate request does not use a DSA key pair as required by the certificate template, but a ECC key pair." | Should -Be $True
    }

    It 'Given the key is not compliant, no certificate is issued (ECDH)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDH_P256
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH

        Test-AppEvent -Date $Now -Message "*The certificate request does not use a DSA key pair as required by the certificate template, but a ECC key pair." | Should -Be $True
    }

}