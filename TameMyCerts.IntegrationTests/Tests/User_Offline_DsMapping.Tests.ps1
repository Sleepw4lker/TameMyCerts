BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_DsMapping"
}

Describe 'User_Offline_DsMapping.Tests' {

    It 'Given a user is not found, no certificate is issued' {

        $Csr = New-CertificateRequest -Upn "NonExistingUser@tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }

    It 'Given a user is found, a certificate is issued' {

        $Csr = New-CertificateRequest -Upn "TestUser1@tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given a user is found but disabled, no certificate is issued' {

        $Csr = New-CertificateRequest -Upn "TestUser3@tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }
    
}