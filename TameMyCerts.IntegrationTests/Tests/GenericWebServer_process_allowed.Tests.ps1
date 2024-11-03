BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_process_allowed"
    
}

Describe 'GenericWebServer_process_allowed.Tests' {

    It 'Given a request is compliant, a certificate is issued' {

        # We explicitly dont't create this request with PSCertificateEnrollment as powershell.exe is not allowed in this test
        $RequestFileName = "$($env:temp)\$((New-Guid).Guid).req"
        [void](& certreq.exe -new "$PSScriptRoot\$($CertificateTemplate).inf" $RequestFileName)
        $Csr = Get-Content -Path $RequestFileName -raw
        
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }

    It 'Given a request is not compliant, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }

}