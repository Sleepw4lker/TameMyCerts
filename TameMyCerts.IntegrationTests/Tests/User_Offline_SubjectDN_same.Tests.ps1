BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_SubjectDN_same"
}

Describe 'User_Offline_SubjectDN_same.Tests' {

    It 'Given a Subject RDN from the CSR is to be written into the outbound DN, a certificate with desired content is issued' {

        $CN = "Thismuststaythesame"
        $Csr = New-CertificateRequest -Subject "CN=$CN"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=$CN"
    }

}