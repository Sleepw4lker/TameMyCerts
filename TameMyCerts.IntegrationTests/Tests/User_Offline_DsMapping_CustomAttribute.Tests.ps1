BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_DsMapping_CustomAttribute"
}

Describe 'User_Offline_DsMapping_CustomAttribute.Tests' {

    It 'Given a mandatory custom attribute is configured, and the attribute is populated, a certificate is issued' {

        $Csr = New-CertificateRequest -Upn "TestUser1@tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "S=Lab Test Value"
    }


    It 'Given a mandatory custom attribute is configured, and the attribute is not populated, no certificate is issued' {

        $Csr = New-CertificateRequest -Upn "TestUser2@tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }

}