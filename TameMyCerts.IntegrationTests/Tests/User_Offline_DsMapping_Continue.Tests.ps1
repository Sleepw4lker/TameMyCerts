BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_DsMapping_Continue"
}

Describe 'User_Offline_DsMapping_Continue.Tests' {

    It 'Given a user is found, a certificate is issued and the security identifier extension is added' {

        $Csr = New-CertificateRequest -Upn "TestUser1@tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate
        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Extensions | Where-Object { $_.Oid.Value.Equals("1.3.6.1.4.1.311.25.2") } | Should -Not -BeNullOrEmpty
    }

    It 'Given a user is not found, a certificate is issued and the security identifier extension is not added' {

        $Csr = New-CertificateRequest -Upn "NonExistingUser@tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate
        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Extensions | Where-Object { $_.Oid.Value.Equals($Oid.szOID_DS_CA_SECURITY_EXT) } | Should -BeNullOrEmpty
    }

}