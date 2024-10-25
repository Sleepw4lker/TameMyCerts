BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_noPolicy"

}

Describe 'GenericWebServer_noPolicy.Tests' {

    It 'Given no policy is defined, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }

    It 'Given no policy is defined, flag is enabled, and SAN attribute is present, no certificate is issued' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:$CertificateTemplate","saN:upn=Administrator@tamemycerts-tests.local"
            # This also tests if request attributes are handled case-insensitive

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2 | Should -Be $EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2
        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.NTE_FAIL
    }

    It 'Given no policy is defined, flag is enabled, and StartDate attribute is present, a certificate is issued with correct date' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $CultureInfo = 'en-US' -as [Globalization.CultureInfo]
        $NextYear = (Get-Date).year +1
        $DayOfWeek = (Get-Date -Year $NextYear -Month 1 -Day 1).ToString("ddd", $CultureInfo)

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:$CertificateTemplate","StartDate:$DayOfWeek, 1 Jan $NextYear 00:00:00 GMT"

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTEENDDATE | Should -Be $EditFlag.EDITF_ATTRIBUTEENDDATE
        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS

        $Result.Certificate.NotBefore | Should -Be (Get-Date -Date "$NextYear-01-01 00:00:00Z")
    }

    It 'Given no policy is defined, flag is enabled, and StartDate extension is invalid, no certificate is issued' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:$CertificateTemplate","StartDate:Mon, 1 Dec 2022 00:00:00 GMT"

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTEENDDATE | Should -Be $EditFlag.EDITF_ATTRIBUTEENDDATE
        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_INVALID_TIME
    }

    It 'Given a denied request due to invalid StartDate is resubmitted by an administrator, a certificate is issued' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:$CertificateTemplate","StartDate:Mon, 1 Dec 2022 00:00:00 GMT"

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTEENDDATE | Should -Be $EditFlag.EDITF_ATTRIBUTEENDDATE
        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.ERROR_INVALID_TIME
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }
}