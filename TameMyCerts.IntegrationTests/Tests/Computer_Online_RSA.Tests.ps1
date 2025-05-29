BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "Computer_Online_RSA"
}

Describe 'Computer_Online_RSA.Tests' {

    It 'Given the key is compliant, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm RSA -KeyLength 1024
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given the key is not compliant, no certificate is issued (key is DSA)' {

        $RequestFileName = "$($env:temp)\$((New-Guid).Guid).req"
        [void](& certreq.exe -new "$PSScriptRoot\Computer_Online_DSA.inf" $RequestFileName)
        $Csr = Get-Content -Path $RequestFileName -raw

        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH

        Test-AppEvent -Date $Now -Message "*The certificate request does not use a RSA key pair as required by the certificate template, but a DSA key pair." | Should -Be $True
    }

    It 'Given the key is not compliant, no certificate is issued (key is ECDSA)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDSA_P256
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH

        Test-AppEvent -Date $Now -Message "*The certificate request does not use a RSA key pair as required by the certificate template, but a ECC key pair." | Should -Be $True
    }

    It 'Given the key is not compliant, no certificate is issued (key is ECDH)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDH_P256
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH

        Test-AppEvent -Date $Now -Message "*The certificate request does not use a RSA key pair as required by the certificate template, but a ECC key pair." | Should -Be $True
    }

    It 'Given the key is not compliant, no certificate is issued (key is too large)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyLength 2048
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH

        Test-AppEvent -Date $Now -Message "*Key length of 2048 Bits is more than the allowed maximum length of 1024 Bits." | Should -Be $True
    }

    It 'Given a denied request due to invalid key is resubmitted by an administrator, a certificate is issued (key is DSA)' {

        $RequestFileName = "$($env:temp)\$((New-Guid).Guid).req"
        [void](& certreq.exe -new "$PSScriptRoot\Computer_Online_DSA.inf" $RequestFileName)
        $Csr = Get-Content -Path $RequestFileName -raw

        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given a denied request due to invalid key is resubmitted by an administrator, a certificate is issued (key is ECDSA)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDSA_P256
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given a denied request due to invalid key is resubmitted by an administrator, a certificate is issued (key is ECDH)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDH_P256
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given a denied request due to invalid key is resubmitted by an administrator, a certificate is issued (key is too large)' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyLength 2048
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

}