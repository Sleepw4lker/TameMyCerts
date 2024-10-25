BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "Computer_Online_NotAfter"
}

Describe 'Computer_Online_NotAfter.Tests' {

    It 'Given an ExpirationDate is configured, a certificate is issued with correct NotAfter date' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDSA_P256
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=$([System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName)"
        $Result.Certificate.NotAfter | Should -Be (Get-Date -Date "2060-12-31 23:59:59Z")
    }

}