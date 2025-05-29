BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "Computer_Online_SupplementServicePrincipalNames"
}

Describe 'Computer_Online_SupplementServicePrincipalNames.Tests' {

    It 'Given SPNs are populated, SAN should contain them' {

        $Csr = New-CertificateRequest -Subject "CN=" -KeyAlgorithm ECDSA_P256
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=$([System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName)"
        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "dNSName=$([System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName)"
        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "dNSName=$($env:COMPUTERNAME)"
    }

}