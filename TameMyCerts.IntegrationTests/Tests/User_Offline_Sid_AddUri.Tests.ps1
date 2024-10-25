BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_Sid_AddUri"

    Import-Module -Name ActiveDirectory
}

Describe 'User_Offline_Sid_AddUri.Tests' {

    It 'Given DS mapping is enabled with SID Uri, it is added to the issued certificate' {

        $MySelf = Get-ADUser -Identity $env:Username
        $MySID = $MySelf.SID

        $Csr = New-CertificateRequest -Subject "CN=$($MySelf.Name)"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate
        
        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "uniformResourceIdentifier=tag:microsoft.com,2022-09-14:sid:$MySID"
            
    }

}