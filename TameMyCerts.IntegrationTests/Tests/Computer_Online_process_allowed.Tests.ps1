BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "Computer_Online_process_allowed"
    
}

Describe 'Computer_Online_process_allowed.Tests' {

    It 'Given a request is compliant, a certificate is issued' {

        # We explicitly dont't create this request with PSCertificateEnrollment as powershell.exe is not allowed in this test
        $RequestFileName = "$($env:temp)\$((New-Guid).Guid).req"
        [void](& certreq.exe -new "$PSScriptRoot\$($CertificateTemplate).inf" $RequestFileName)
        $Csr = Get-Content -Path $RequestFileName -raw
        
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=$([System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName)"
    }

    It 'Given a request is not compliant, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal" -KeyAlgorithm ECDSA_P256
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }

}