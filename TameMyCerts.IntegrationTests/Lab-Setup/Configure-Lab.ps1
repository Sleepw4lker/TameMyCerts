<#
    .SYNOPSIS
    Deploys the Lab Environment after the domain has been set up.
#>

#Requires -Modules ServerManager,ActiveDirectory,PowerShellGet

[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CaName = "TEST-CA",

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ConfigNC = "CN=Configuration,DC=tamemycerts-tests,DC=local",

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $DomainName = "DC=tamemycerts-tests,DC=local"
)

New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_2016 -Value 14393

If ([int](Get-WmiObject -Class Win32_OperatingSystem).BuildNumber -lt $BUILD_NUMBER_WINDOWS_2016) {
    Write-Error -Message "This must be run on Windows Server 2016 or newer! Aborting."
    Return 
}

If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error -Message "This must be run as Administrator! Aborting."
    Return
}

If (-not (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
    Write-Error "You must install the domain first!"
    Return
}

$BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

#region Declare functions

Function Set-EnrollPermission {

    param (
        [Parameter(Mandatory=$True)]
        [String]
        $Path,

        [Parameter(Mandatory=$False)]
        [System.Security.Principal.SecurityIdentifier]
        $SecurityIdentifier = "S-1-5-11"
    )

    $Acl = Get-ACL -Path $Path
    
    $Ace = New-Object -TypeName System.DirectoryServices.ExtendedRightAccessRule -ArgumentList @(
        $SecurityIdentifier
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.Guid]"0E10C968-78FB-11D2-90D4-00C04F79DC55"
    );

    $Acl.AddAccessRule($Ace) 

    Set-Acl -Path $Path -AclObject $Acl 
}

Function New-TemplateOID {

    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $ConfigNC
    )

    $ForestOid = Get-ADObject `
        -Identity "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
        -Properties msPKI-Cert-Template-OID | Select-Object -ExpandProperty msPKI-Cert-Template-OID

    do {

        $OidSuffix1 = Get-Random -Minimum 1000000  -Maximum 99999999
        $OidSuffix2 = Get-Random -Minimum 10000000 -Maximum 99999999
        $Oid = "$ForestOid.$OidSuffix1.$OidSuffix2"

    } until (-not (Get-OIDObject -Oid $Oid -ConfigNC $ConfigNC))

    Return $Oid
}

Function Get-OIDObject {

    param (
        [Parameter(Mandatory=$True)]
        [String]
        $Oid,

        [Parameter(Mandatory=$True)]
        [String]
        $ConfigNC 
    )

    return Get-ADObject `
        -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
        -Filter {msPKI-Cert-Template-OID -eq $Oid}
}

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

#endregion

#region Configure Domain Environment

Write-Host "Provisioning users and groups"

New-ADOrganizationalUnit `
    -Name "TameMyCerts Users" `
    -Path $DomainName `
    -ProtectedFromAccidentalDeletion $True

# The user doesnt really matter as this is a throw-away lab
Add-Type -AssemblyName System.Web
$Password = [System.Web.Security.Membership]::GeneratePassword(16,0) | ConvertTo-SecureString -AsPlainText -Force

(1..7) | ForEach-Object -Process {

    New-ADUser `
        -SamAccountName "TestUser$($_)" `
        -UserPrincipalName "testuser$($_)@tamemycerts-tests.local" `
        -Name "Test User $($_)" `
        -GivenName "Test" `
        -Surname "User $($_)" `
        -Path "OU=TameMyCerts Users,$DomainName" `
        -Enabled $True `
        -AccountPassword $Password

}

New-ADOrganizationalUnit `
    -Name "TameMyCerts Groups" `
    -Path $DomainName `
    -ProtectedFromAccidentalDeletion $True


"An allowed Group",
"An indirectly allowed Group",
"A forbidden Group" | ForEach-Object -Process {

    New-ADGroup `
        -Name "$($_)" `
        -SamAccountName $($_).Replace(" ", "") `
        -GroupCategory Security `
        -GroupScope Global `
        -DisplayName $($_) `
        -Path "OU=TameMyCerts Groups,$DomainName" `
        -Description $($_)

}

Get-ADUser Administrator | Set-ADUser -UserPrincipalName "Administrator@tamemycerts-tests.local"
Get-ADGroup -Identity "AnallowedGroup" | Add-ADGroupMember -Members "Administrator"
Get-ADGroup -Identity "AnallowedGroup" | Add-ADGroupMember -Members "TestUser1"
Get-ADGroup -Identity "AnallowedGroup" | Add-ADGroupMember -Members "TestUser2"
Get-ADGroup -Identity "AnallowedGroup" | Add-ADGroupMember -Members "AnindirectlyallowedGroup" 
Get-ADGroup -Identity "AnindirectlyallowedGroup" | Add-ADGroupMember -Members "TestUser6"
Get-ADGroup -Identity "AforbiddenGroup" | Add-ADGroupMember -Members "TestUser2"
Disable-ADAccount -Identity "TestUser3"
Get-ADUser -Identity "TestUser4" | Move-ADObject -TargetPath "CN=Users,$DomainName"
Get-ADUser TestUser7 | Set-ADUser -Clear UserPrincipalName

"co", "company", "department", "departmentNumber", "description", "displayName", "division", "employeeID", "employeeNumber", "employeeType", "facsimileTelephoneNumber", "gecos", 
"homePhone", "homePostalAddress", "info", "l", "mail", "middleName", "mobile",  "otherMailbox", "otherMobile", "otherPager", "otherTelephone", "pager", "personalTitle", 
"postalAddress", "postalCode", "postOfficeBox", "st", "street", "streetAddress", "telephoneNumber", "title" | ForEach-Object -Process {

    Set-ADUser -Identity TestUser1 -Add @{$_ = "v-$_"}

}

Set-ADUser -Identity TestUser1 -Add @{c = "DE"}

#endregion

#region Setup Enterprise Certification Authority

Write-Host "Installing certification authority"

[void](Remove-Item -Path "$($env:SystemRoot)\capolicy.inf" -Force -ErrorAction SilentlyContinue)
        
[System.IO.File]::WriteAllText(
    "$($env:SystemRoot)\capolicy.inf",
    (Get-Content -Path "$(Split-Path -Path $MyInvocation.MyCommand.Definition -Parent)\capolicy.inf" -Encoding UTF8 -Raw),
    [System.Text.Encoding]::GetEncoding('iso-8859-1')
    )

$CaDbDir = "$($env:SystemRoot)\System32\CertLog"
$CaDbLogDir = "$($env:SystemRoot)\System32\CertLog"

[void](New-Item -Path $CaDbDir -ItemType Directory -ErrorAction SilentlyContinue)
[void](New-Item -Path $CaDbLogDir -ItemType Directory -ErrorAction SilentlyContinue)

$CaDeploymentParameters = @{
    CACommonName = $CaName
    DatabaseDirectory = $CaDbDir
    LogDirectory = $CaDbLogDir
    HashAlgorithm = "SHA256"
    CryptoProviderName = "RSA#Microsoft Software Key Storage Provider"
    OverwriteExistingKey = $True
    OverwriteExistingDatabase = $True
    Force = $True
    CAType = "EnterpriseRootCA"
    KeyLength = 4096
    ValidityPeriod = "Years"
    ValidityPeriodUnits = 50
}

[void](Install-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools)

[void](Install-AdcsCertificationAuthority @CaDeploymentParameters)

[void](& certutil -setreg CA\LogLevel 4)
[void](& certutil -setreg CA\ValidityPeriodUnits 50)

# Though this is insecure, we enable the flag in the lab to test the logic inside TameMyCerts
[void](& certutil -setreg Policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2)
[void](& certutil -setreg Policy\EditFlags +EDITF_ATTRIBUTEENDDATE)
[void](& certutil -setreg CA\CRLFlags +CRLF_ALLOW_REQUEST_ATTRIBUTE_SUBJECT)

[void](& certutil -setreg CA\SubjectTemplate +Title)
[void](& certutil -setreg CA\SubjectTemplate +GivenName)
[void](& certutil -setreg CA\SubjectTemplate +Initials)
[void](& certutil -setreg CA\SubjectTemplate +SurName)
[void](& certutil -setreg CA\SubjectTemplate +StreetAddress)
[void](& certutil -setreg CA\SubjectTemplate +UnstructuredName)
[void](& certutil -setreg CA\SubjectTemplate +UnstructuredAddress)
[void](& certutil -setreg CA\SubjectTemplate +DeviceSerialNumber)

Restart-Service -Name CertSvc

# endregion

#region Import Certificate Templates

Write-Host "Importing certificate templates"

$Templates = Get-ChildItem -Path "$BaseDirectory\..\Tests\*.ldf" | 
    Select-Object -ExpandProperty Name | 
        ForEach-Object -Process { $_.Split(".")[0] }

ForEach ($TemplateName in $Templates) {

    $FilePath = "$BaseDirectory\..\Tests\$TemplateName.ldf"

    # This is a special case
    if ($TemplateName -eq "SpecialChars") { $TemplateName = "SpecialChars_Üöäß/&|()." }

    Write-Host "Importing $TemplateName"

    $TemplatePath = "CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

    If (Test-Path -Path "AD:$TemplatePath") {continue}

    Write-Verbose -Message "Importing $TemplateName"

    # Import template from LDIF

    [void](& ldifde -i -f $FilePath)

    # Restore OID object

    $TemplateOid = New-TemplateOID -ConfigNC $ConfigNC
    Set-AdObject -Identity $TemplatePath -Replace @{"msPKI-Cert-Template-OID" = $TemplateOid}

    # This is a trick that will restore the msPKI-Enterprise-OID object which is linked to the pKICertificateTemplate object
    [void](& certutil -f -oid $TemplateOid $TemplateName)

    Get-OIDObject -Oid $TemplateOid -ConfigNC $ConfigNC | 
        Set-AdObject -Replace @{DisplayName = $TemplateName}

    # Grant Enroll permissions to everyone
    Set-EnrollPermission -Path "AD:$TemplatePath"
}

Write-Host "Updating caches"

Stop-Service -Name CertSvc

[void](& certutil -pulse)
[void](& certutil -pulse -user)

do {
    Start-Sleep -Seconds 1
} while (
    (Get-ScheduledTask -TaskPath \Microsoft\Windows\CertificateServicesClient\ -TaskName SystemTask).State -eq "Running" -or
    (Get-ScheduledTask -TaskPath \Microsoft\Windows\CertificateServicesClient\ -TaskName UserTask).State -eq "Running"
)

Start-Service -Name CertSvc

do {
    Start-Sleep -Seconds 1
} while (-not (Test-AdcsServiceAvailability))

# Publish all imported templates
ForEach ($TemplateName in $Templates) {

    # This is a special case
    if ($TemplateName -eq "SpecialChars") { $TemplateName = "SpecialChars_Üöäß/&|()." }

    Write-Host "Binding $TemplateName to CA"
    [void](& certutil -setCAtemplates +$TemplateName)
}

# endregion

#region Request Enrollment Aqent certificate

Write-Host "Requesting Enrollment Agent certificate"

[void](& certutil -user -pulse)
Start-Sleep -Seconds 60
[void](& certreq -q -enroll TestLabEnrollmentAgent)

#endregion

#region Install Dependencies

Write-Host "Installing PowerShell Modules"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

[void](Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force)
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

Install-Module -Name "PSCertificateEnrollment" -MinimumVersion 1.0.9 -Force
Install-Module -Name "Pester" -Force -SkipPublisherCheck

#endregion