BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_Sid_Deny"
}

Describe 'User_Offline_Sid_Deny.Tests' {

    It 'Given a SID extension is requested, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=TestUser1" -Sid "S-1-5-21-1471894826-1984196480-850735463-500"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }

    It 'Given a denied request due to denied SID extension is resubmitted by an administrator, a certificate with SID extension is issued' {

        $Csr = New-CertificateRequest -Subject "CN=TestUser1" -Sid "S-1-5-21-1471894826-1984196480-850735463-500"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        [bool]($Result2.Certificate.Extensions | Where-Object {$_.Oid.Value -eq $Oid.szOID_DS_CA_SECURITY_EXT }) | 
            Should -Be $True
    }

}