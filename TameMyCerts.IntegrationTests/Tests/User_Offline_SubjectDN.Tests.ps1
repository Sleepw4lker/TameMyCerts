BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_SubjectDN"
}

Describe 'User_Offline_SubjectDN.Tests' {

    It 'Given a Subject RDN from DS mapping is enabled and not all attributes are populated, a certificate with desired content is issued' {

        $Csr = New-CertificateRequest -Upn "TestUser2@tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=testuser2@tmctests.internal, G=Test, SN=User 2"
    }

}