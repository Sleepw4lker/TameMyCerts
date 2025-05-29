BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_brokenPolicy"
}

Describe 'GenericWebServer_brokenPolicy.Tests' {

    It 'Given the policy file is broken, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal" -KeyLength 2048
        $Now = Get-Date
        
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.NTE_FAIL

        Test-AppEvent -Id 10 -Date $Now -Message "*There is an error in XML document (0, 0). Root element is missing." | Should -Be $True
    }
}