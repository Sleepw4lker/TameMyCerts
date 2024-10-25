BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "Computer_Online_CSP_allowed"
}

Describe 'Computer_Online_CSP_allowed.Tests' {

    It 'Given a request is compliant, a certificate is issued' {

        $Csr = New-CertificateRequest  -KeyLength 2048 -Subject "CN=" -Ksp "Microsoft Software Key Storage Provider"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=$([System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName)"
    }

    It 'Given a request is not compliant, no certificate is issued' {

        $Csr = New-CertificateRequest  -KeyLength 2048 -Subject "CN=" -Ksp "Microsoft Enhanced RSA and AES Cryptographic Provider"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }

}