BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_SubjectFromRequest"
}

Describe 'GenericWebServer_SubjectFromRequest.Tests' {

    It 'Given a request is compliant, a certificate is issued (commonName only)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }

    It 'Given a request is not compliant, no certificate is issued (no commonName)' {

        $Csr = New-CertificateRequest -Dns "www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (countryName invalid)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local,C=UK"
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

        $Csr = New-CertificateRequest -Subject "CN=wwpornw.intra.tamemycerts-tests.local"
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

    It 'Given a request is compliant, a certificate is issued and SAN is supplemented (fully qualified)' {

        $Identity = "www.intra.tamemycerts-tests.local"
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
    
    It 'Given a request is compliant, and contains multiple fileds of same type, a certificate is issued' {

        $Identity1 = "www.intra.tamemycerts-tests.local"
        $Identity2 = "this-is-a-test"
        $Identity3 = "192.168.0.1"
        $Csr = New-CertificateRequest -Subject "CN=$Identity1,CN=$Identity2,CN=$Identity3"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=$Identity3, CN=$Identity2, CN=$Identity1"
        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "dNSName=$Identity1"
        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "dNSName=$Identity2"
        $Result.Certificate | Get-SubjectAlternativeNames | Select-Object -ExpandProperty SAN | Should -Contain "iPAddress=$Identity3"
    }

    It 'Given a request containing custom OID is compliant, a certificate is issued (commonName only)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local,OID.1.2.3.4=test"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }

    It 'Given a request containing custom OID is not compliant, no certificate is issued (no commonName)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local,OID.1.2.3.4=this-should-fail"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }
}