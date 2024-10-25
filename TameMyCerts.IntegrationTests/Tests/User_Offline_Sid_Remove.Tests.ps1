BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_Sid_Remove"
}

Describe 'User_Offline_Sid_Remove.Tests' {

    It 'Given a SID extension is requested, a certificate without SID extension is issued' {

        $Csr = New-CertificateRequest -Subject "CN=TestUser1" -Sid "S-1-5-21-1471894826-1984196480-850735463-500"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        [bool]($Result.Certificate.Extensions | Where-Object {$_.Oid.Value -eq $Oid.szOID_DS_CA_SECURITY_EXT }) | 
            Should -Be $False
    }

}