BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_SubjectDN_Mandatory"
}

Describe 'User_Offline_SubjectDN_Mandatory.Tests' {

    It 'Given a Subject RDN from DS mapping is enabled and all mandatory attributes are populated, a certificate with desired content is issued' {

        $Csr = New-CertificateRequest -Subject "CN=TestUser1" -Upn "TestUser1@tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "E=v-mail, CN=v-displayName, OU=v-department, O=v-company, L=v-l, S=v-st, C=DE, T=v-title, G=Test, SN=User 1, STREET=v-streetAddress"
    }

    It 'Given a Subject RDN from DS mapping is enabled and not all mandatory attributes are populated, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=TestUser2" -Upn "TestUser2@tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED

    }

    It 'Given a denied request due to missing mandatory attributes is resubmitted by an administrator, a certificate is issued and Subject DN is not modified' {

        $Csr = New-CertificateRequest -Subject "CN=TestUser2" -Upn "TestUser2@tamemycerts-tests.local"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result2.Certificate.Subject | Should -Be "CN=TestUser2, G=Test, SN=User 2"
    }

}