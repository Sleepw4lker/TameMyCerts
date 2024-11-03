Function Test-AdcsServiceAvailability {

    [cmdletbinding()]
    param()

    New-Variable -Option Constant -Name CC_LOCALCONFIG -Value 0x00000003
    New-Variable -Option Constant -Name CR_PROP_CANAME -Value 0x00000006
    New-Variable -Option Constant -Name PROPTYPE_STRING -Value 4

    $CertConfig = New-Object -ComObject CertificateAuthority.Config
    $ConfigString = $CertConfig.GetConfig($CC_LOCALCONFIG)
    $CertAdmin = New-Object -ComObject CertificateAuthority.Admin.1

    Try {
        [void]($CertAdmin.GetCAProperty($ConfigString, $CR_PROP_CANAME, 0, $PROPTYPE_STRING,0))
        Return $True
    }
    Catch {
        Return $False
    }

}

Function Get-SubjectAlternativeNames {

    [CmdletBinding()]
    param(
        [Parameter(  
            Mandatory = $True,   
            ValueFromPipeline = $True
        )]
        [X509Certificate]
        $Certificate
    )

    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64 -Value 1
    New-Variable -Option Constant -Name XCN_OID_SUBJECT_ALT_NAME2 -Value "2.5.29.17"

    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_RFC822_NAME -Value 2
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_DNS_NAME -Value 3
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_URL -Value 7
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_IP_ADDRESS -Value 8
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME -Value 11

    $Certificate.Extensions | Where-Object {$_.Oid.Value -eq $XCN_OID_SUBJECT_ALT_NAME2} | Foreach-Object -Process {

        $AlternativeNames = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
                
        $AlternativeNames.InitializeDecode($XCN_CRYPT_STRING_BASE64,  [Convert]::ToBase64String($_.RawData)) 

        Foreach ($AlternativeName in $AlternativeNames.AlternativeNames) {

            switch ($AlternativeName.Type) {

                $XCN_CERT_ALT_NAME_DNS_NAME {
                    [PSCustomObject] @{ SAN = "dNSName=$($AlternativeName.strValue)" }
                }
    
                $XCN_CERT_ALT_NAME_IP_ADDRESS {
                    [PSCustomObject] @{ SAN = "iPAddress=$([IPAddress] ([Convert]::FromBase64String($AlternativeName.RawData($XCN_CRYPT_STRING_BASE64))))" }
                }
                
                $XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME {
                    [PSCustomObject] @{ SAN = "userPrincipalName=$($AlternativeName.strValue)"}
                }
    
                $XCN_CERT_ALT_NAME_RFC822_NAME {
                    [PSCustomObject] @{ SAN = "rfc822Name=$($AlternativeName.strValue)"}
                }
    
                $XCN_CERT_ALT_NAME_URL {
                    [PSCustomObject] @{ SAN = "uniformResourceIdentifier=$($AlternativeName.strValue)"}
                }
            }
        }
        
        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNames))
    }
}

Function Test-AppEvent {

    [cmdletbinding()]
    param(
        [Int]
        $Id = 6,

        [DateTime]
        $Date = (Get-Date),

        [String]
        $Message
    )

    return [bool](
        Get-WinEvent -FilterHashtable @{
            Logname='Application'
            ProviderName=@('TameMyCerts')
            Id=@($Id)
            StartTime=($Date)
        } -ErrorAction SilentlyContinue | Where-Object { $_.Message -like $Message }
    )
}

function New-SignedCertificateRequestWithSan {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory=$True, ValuefromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateRequest,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_.HasPrivateKey) -and ($null -ne $_.PSParentPath)})]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $SigningCert,

        [Alias("DnsName")]
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            $_ | ForEach-Object -Process {
                [System.Uri]::CheckHostName($_) -eq [System.UriHostnameType]::Dns
            }
        })]
        [String[]]
        $Dns

    )

    begin {

        $CertRequestPkcs10 = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestPkcs10'
        $CertRequestCmc = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestCmc'

        $XCN_CRYPT_STRING_BASE64 = 1    
        $VerifyNone = 0
        $XCN_CRYPT_HASH_ALG_OID_GROUP_ID = 1
        $AlgorithmFlagsNone = 0
        $XCN_CERT_ALT_NAME_DNS_NAME = 3
        $CR_OUT_BASE64 = 1
    }

    process {

        $CertRequestPkcs10.InitializeDecode($CertificateRequest, $EncodingType.XCN_CRYPT_STRING_BASE64_ANY)

        $CertRequestCmc.InitializeFromInnerRequest($CertRequestPkcs10)

        $SignerCertificate =  New-Object -ComObject 'X509Enrollment.CSignerCertificate'
        $SignerCertificate.Initialize(
            [int]($SigningCert.PSParentPath -match "Machine"),
            $VerifyNone,
            $XCN_CRYPT_STRING_BASE64,
            [Convert]::ToBase64String($SigningCert.RawData)
        )
        $CertRequestCmc.SignerCertificate = $SignerCertificate

        $HashAlgorithmObject = New-Object -ComObject X509Enrollment.CObjectId
        $HashAlgorithmObject.InitializeFromAlgorithmName(
            $XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
            $XCN_CRYPT_OID_INFO_PUBKEY_ANY,
            $AlgorithmFlagsNone,
            "SHA256"
        )
        $CertRequestCmc.HashAlgorithm = $HashAlgorithmObject

        $SubjectAlternativeNamesExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
        $Sans = New-Object -ComObject X509Enrollment.CAlternativeNames

        Foreach ($Entry in $Dns) {
        
            $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
            $AlternativeNameObject.InitializeFromString($XCN_CERT_ALT_NAME_DNS_NAME, $Entry)
            $Sans.Add($AlternativeNameObject)
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNameObject))

        }

        $SubjectAlternativeNamesExtension.Critical = $True
        $SubjectAlternativeNamesExtension.InitializeEncode($Sans)
        $CertRequestCmc.X509Extensions.Add($SubjectAlternativeNamesExtension)
        
        $CertRequestCmc.Encode()

        $CertRequestCmc.RawData($CR_OUT_BASE64)

    }

    end {
        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertRequestPkcs10))
        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertRequestCmc))
        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($HashAlgorithmObject))
    }

}

$TestStartTime = Get-Date

Import-Module -Name PSCertificateEnrollment -MinimumVersion "1.0.9" -ErrorAction Stop

$CaName = "TEST-CA"
$DomainName = "tamemycerts-tests.local"
$ConfigString = "$($env:ComputerName).$DomainName\$CaName"

New-Variable -Option Constant -Name WinError -Value @{
    ERROR_SUCCESS = 0x0
    ERROR_INVALID_TIME = 0x8007076d
    NTE_FAIL = 0x80090020
    CERTSRV_E_TEMPLATE_DENIED = 0x80094012
    CERTSRV_E_BAD_REQUESTSUBJECT = 0x80094001
    CERTSRV_E_UNSUPPORTED_CERT_TYPE = 0x80094800
    CERTSRV_E_KEY_LENGTH = 0x80094811
    CERT_E_INVALID_NAME = 0x800b0114
}

New-Variable -Option Constant -Name CertCli -Value @{
    CR_DISP_INCOMPLETE = 0
    CR_DISP_ERROR = 1
    CR_DISP_DENIED = 2
    CR_DISP_ISSUED = 3
    CR_DISP_ISSUED_OUT_OF_BAND = 4
    CR_DISP_UNDER_SUBMISSION = 5
    CR_DISP_REVOKED = 6
}

New-Variable -Option Constant -Name Oid -Value @{

    szOID_DS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2"
    XCN_OID_ENROLLMENT_AGENT = "1.3.6.1.4.1.311.20.2.1"
    XCN_OID_SUBJECT_ALT_NAME2 = "2.5.29.17"
    XCN_OID_CRL_DIST_POINTS = "2.5.29.31"
    XCN_OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1"
}

New-Variable -Option Constant -Name EditFlag -Value @{
    EDITF_ATTRIBUTEENDDATE = 0x20
    EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x40000
}