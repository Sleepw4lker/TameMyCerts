BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_DenyIfExisting"
}

Describe 'User_Offline_DenyIfExisting.Tests' {

    It 'Given a user is not found, a certificate is issued' {

        $Csr = New-CertificateRequest -Upn "NonExistingUser@tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate
        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given a user is found, no certificate is issued' {

        $Csr = New-CertificateRequest -Upn "TestUser1@tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }

}