BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_SubjectAltName_Mandatory"
}

Describe 'User_Offline_SubjectAltName_Mandatory.Tests' {

    It 'Given a SAN from DS mapping is enabled and all mandatory attributes are populated, a certificate with desired content is issued' {

        $Csr = New-CertificateRequest -Subject "CN=TestUser1"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "userPrincipalName=TestUser1@tmctests.internal"
    }

        It 'Given a SAN from DS mapping is enabled and not all mandatory attributes are populated, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=TestUser7"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED

    }

    It 'Given a denied request due to missing mandatory attributes is resubmitted by an administrator, a certificate is issued and SAN is not modified' {

        $Csr = New-CertificateRequest -Subject "CN=TestUser7"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result2.Certificate.Subject | Should -Be "CN=TestUser7"
        $Result2.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Not -Contain "userPrincipalName=TestUser7@tmctests.internal"
    }

}