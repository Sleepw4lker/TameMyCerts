BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_SubjectOnly"
}

# TODO: I don't understand what this test is good for...

Describe 'GenericWebServer_SubjectOnly.Tests' {

    It 'Given a request is compliant, a certificate is issued' {

        # We explicitly dont't create this request with PSCertificateEnrollment as powershell.exe is not allowed in this test
        $RequestFileName1 = "$($env:temp)\$((New-Guid).Guid).req"
        $RequestFileName2 = "$($env:temp)\$((New-Guid).Guid).req"
        $SigningCertificate = (Get-ChildItem -Path Cert:\CurrentUser\My | 
            Where-Object { $_.EnhancedKeyUsageList.ObjectId -Contains $Oid.XCN_OID_ENROLLMENT_AGENT }).Thumbprint

        $Csr1 = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Csr1 | Out-File -FilePath $RequestFileName1 -Force

        (& certreq -q -cert $SigningCertificate -policy $RequestFileName1 "$PSScriptRoot\$($CertificateTemplate).inf" $RequestFileName2)
        
        $Csr2 = Get-Content -Path $RequestFileName2 -raw
        
        $Result = $Csr2 | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }
}