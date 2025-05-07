BeforeAll {

    . "C:\INSTALL\TameMyCerts\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer"
}

Describe 'GenericWebServer.Tests' {

    It 'Given a request is compliant, a certificate is issued (commonName only)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tmctests.internal"
    }

    It 'Given a request is compliant but a RDN is put via Attributes, no certificate is issued' {

        <# CRLF_ALLOW_REQUEST_ATTRIBUTE_SUBJECT must be enabled for this #>
        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal"
        $Now = Get-Date
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:$CertificateTemplate", "OU:willyoufindme?" # This is **not** allowed
        
        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME

        Test-AppEvent -Date $Now -Message "*The organizationalUnitName field is not allowed." | Should -Be $True
    }

    It 'Given a request contains a forbidden SAN in signed CMC layer, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal"
        $SigningCertificate = (Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.EnhancedKeyUsageList.ObjectId -Contains $Oid.XCN_OID_ENROLLMENT_AGENT })
        $SignedCsr = $Csr | New-SignedCertificateRequestWithSan -SigningCert $SigningCertificate -Dns "will.you-find.me" # This is **not** allowed
        $Now = Get-Date
        $Result = $SignedCsr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME

        Test-AppEvent -Date $Now -Message "*will.you-find.me*" | Should -Be $True
    }

    It 'Given a request contains unknown RDNs, a certificate is issued (without them)' {

        # Not detected but ignored
        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal,OID.1.2.3.4=test"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Match "CN=www.intra.tmctests.internal"
        $Result.Certificate.Subject | Should -Not -Match "OID.1.2.3.4"
    }

    It 'Given a request is compliant, a certificate is issued (commonName and iPAddress)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal" -IP "192.168.101.1"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tmctests.internal"
    }

    It 'Given a request is compliant, a certificate is issued (commonName and dNSName)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal" -Dns "www.intra.tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tmctests.internal"
    }

    It 'Given a request is not compliant, no certificate is issued (no commonName)' {

        $Csr = New-CertificateRequest -Dns "www.intra.tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (countryName invalid)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal,C=UK"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (commonName not allowed)' {

        $Csr = New-CertificateRequest -Subject "CN=www.this-is-an-invalid-dns-name.org"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (commonName forbidden)' {

        $Csr = New-CertificateRequest -Subject "CN=wwpornw.intra.tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (iPAddress not allowed)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal" -IP "192.168.0.1"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (dNSName not allowed)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal" -Dns "www.this-is-an-invalid-dns-name.org"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (userPrincipalName not defined)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal" -Upn "Administrator@intra.tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (commonName too short)' {

        $Csr = New-CertificateRequest -Subject "CN=,C=DE"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a denied request is resubmitted by an admin, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=,C=DE"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given flag is enabled, and SAN attribute is present, no certificate is issued' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:$CertificateTemplate","saN:upn=Administrator@tmctests.internal"
            # This also tests if request attributes are handled case-insensitive

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2 | Should -Be $EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2
        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.NTE_FAIL
    }

    It 'Given flag is enabled, and StartDate attribute is present, a certificate is issued with correct date' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $CultureInfo = 'en-US' -as [Globalization.CultureInfo]
        $NextYear = (Get-Date).year +1
        $DayOfWeek = (Get-Date -Year $NextYear -Month 1 -Day 1).ToString("ddd", $CultureInfo)

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:$CertificateTemplate","StartDate:$DayOfWeek, 1 Jan $NextYear 00:00:00 GMT"

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTEENDDATE | Should -Be $EditFlag.EDITF_ATTRIBUTEENDDATE
        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS

        $Result.Certificate.NotBefore | Should -Be (Get-Date -Date "$NextYear-01-01 00:00:00Z")
    }

    It 'Given flag is enabled, and StartDate extension is invalid, no certificate is issued' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:$CertificateTemplate","StartDate:Mon, 1 Dec 2022 00:00:00 GMT"

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTEENDDATE | Should -Be $EditFlag.EDITF_ATTRIBUTEENDDATE
        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_INVALID_TIME
    }

    It 'Given a denied request due to invalid StartDate is resubmitted by an administrator, a certificate is issued' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tmctests.internal"
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

    It 'Given a request is compliant, a certificate is issued and SAN is supplemented (fully qualified)' {

        $Identity = "www.intra.tmctests.internal"
        $Csr = New-CertificateRequest -Subject "CN=$Identity"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=$Identity"
        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "dNSName=$Identity"
    }

    It 'Given a request is compliant, a certificate is issued and SAN is supplemented (non-qualified)' {

        $Identity = "this-is-a-test"
        $Csr = New-CertificateRequest -Subject "CN=$Identity"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=$Identity"
        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "dNSName=$Identity"
    }

    It 'Given a request is compliant, a certificate is issued and SAN is supplemented (IPv4)' {

        $Identity = "192.168.0.1"
        $Csr = New-CertificateRequest -Subject "CN=$Identity"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=$Identity"
        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "iPAddress=$Identity"
    }
    
    It 'Given a request is compliant, and contains multiple fields of same type, the request is denied' {

        $Identity1 = "www.intra.tmctests.internal"
        $Identity2 = "this-is-a-test"
        $Identity3 = "192.168.0.1"
        $Csr = New-CertificateRequest -Subject "CN=$Identity1,CN=$Identity2,CN=$Identity3"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }
}