BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_noPolicy_pending"

}

Describe 'GenericWebServer_noPolicy_pending.Tests' {

    It 'Given no policy is defined, a certificate is put into pending state' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_UNDER_SUBMISSION
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    
    It 'Given a pending request is resubmitted by an admin, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_UNDER_SUBMISSION
        $Result1.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result2.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }
}