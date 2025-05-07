BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_Pattern"
}

Describe 'User_Offline_Pattern.Tests' {

    It 'Given a DS attribute does not hit the blacklisted pattern, a certificate is issued' {

        $Csr = New-CertificateRequest -Upn "TestUser1@tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given a DS attribute does hit the blacklisted pattern, no certificate is issued' {

        $Csr = New-CertificateRequest -Upn "TestUser2@tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }

}