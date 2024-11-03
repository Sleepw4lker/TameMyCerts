BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "GenericWebServer_SubjectFromRequest_AllRdnTypes"
}

Describe 'GenericWebServer_SubjectFromRequest_AllRdnTypes.Tests' {

    It 'Given a request is compliant, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "E=emailAddress,CN=commonName,DC=domainComponent,O=organizationName,OU=organizationalUnitName,L=localityName,S=stateOrProvinceName,C=DE,T=title,G=givenName,I=ABC,SN=surname,STREET=streetAddress,OID.1.2.840.113549.1.9.2=unstructuredName,OID.1.2.840.113549.1.9.8=unstructuredAddress,SERIALNUMBER=serialNumber"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Match "E=emailAddress"
        $Result.Certificate.Subject | Should -Match "CN=commonName"
        $Result.Certificate.Subject | Should -Match "DC=domainComponent"
        $Result.Certificate.Subject | Should -Match "O=organizationName"
        $Result.Certificate.Subject | Should -Match "OU=organizationalUnitName"
        $Result.Certificate.Subject | Should -Match "L=localityName"
        $Result.Certificate.Subject | Should -Match "S=stateOrProvinceName"
        $Result.Certificate.Subject | Should -Match "C=DE"
        $Result.Certificate.Subject | Should -Match "T=title"
        $Result.Certificate.Subject | Should -Match "G=givenName"
        $Result.Certificate.Subject | Should -Match "I=ABC"
        $Result.Certificate.Subject | Should -Match "SN=surname"
        $Result.Certificate.Subject | Should -Match "STREET=streetAddress"
        $Result.Certificate.Subject | Should -Match "OID.1.2.840.113549.1.9.2=unstructuredName"
        $Result.Certificate.Subject | Should -Match "OID.1.2.840.113549.1.9.8=unstructuredAddress"
        $Result.Certificate.Subject | Should -Match "SERIALNUMBER=serialNumber"
    }

    It 'Given a request is missing required RDNs, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "E=emailAddress,CN=commonName,DC=domainComponent,O=organizationName,OU=organizationalUnitName,L=localityName,S=stateOrProvinceName,C=DE"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request contains invalid RDNs, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "E=invalid,CN=commonName,DC=domainComponent,O=organizationName,OU=organizationalUnitName,L=localityName,S=stateOrProvinceName,C=DE"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a denied request is resubmitted by an admin, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "E=emailAddress,CN=commonName,DC=domainComponent,O=organizationName,OU=organizationalUnitName,L=localityName,S=stateOrProvinceName,C=DE"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

}