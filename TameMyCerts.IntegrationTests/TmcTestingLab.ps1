#requires -Modules Hyper-V,NetNat -PSEdition Core
[cmdletbinding()]
param(
    [Parameter(Mandatory=$True)]
    [ValidatePattern("^[a-zA-Z0-9]{4,8}$")]
    [ValidateScript({$LabPrefix = $_; -not [bool](Get-VM | Where-Object { $_.Name.StartsWith($LabPrefix) })})]
    [ValidateScript({$LabPrefix = $_; -not [bool](Get-VMSwitch | Where-Object { $_.Name.StartsWith($LabPrefix) })})]
    [string]
    $LabPrefix,

    [Parameter(Mandatory=$True)]
    [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")]
    [String]
    $AddressSpace,

    [Parameter(Mandatory=$True)]
    [ValidateScript({($_ | ConvertFrom-SecureString -AsPlaintext) -match "(?-i)(?:([a-z])|([A-Z])|(\d)|([!@#\$%\^&])){8,}"})]
    [securestring]
    $Password,

    [Parameter(Mandatory=$False)]
    [ValidateScript({(Get-LabAvailableOperatingSystem | Select-Object -ExpandProperty OperatingSystemName).Contains($_)})]
    [String]
    $ServerOperatingSystem = "Windows Server 2025 Standard Evaluation (Desktop Experience)",

    [Switch]
    $Nat
)

function Get-HostIpAddress {

    param($AddressSpace)

    $parts = $AddressSpace.Split("/")[0].Split(".")
    $hostip = "$($parts[0]).$($parts[1]).$($parts[2]).$([int]$parts[3] + 1)"

    return $hostip
}

$HostAddress = Get-HostIpAddress -AddressSpace $AddressSpace

if (Get-NetIPAddress | Where-Object { $_.IPAddress -eq $HostAddress}) {
    Write-Error -Message "$AddressSpace is already in use!" -ErrorAction Stop
}

# Only A-Z, a-z and 0-9 are allowed.
$LabName = "$($LabPrefix)TmcTests"

$DomainController = "$($LabPrefix)-DC01"

$DomainName = "TMCTESTS"
$DomainFqdn = "$($DomainName.ToLower()).internal"

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -ReferenceDiskSizeInGB 127

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:DomainName' = $DomainFqdn
    'Add-LabMachineDefinition:TimeZone' = 'W. Europe Standard Time'
    'Add-LabMachineDefinition:MinMemory' = 512MB
    'Add-LabMachineDefinition:Memory' = 1GB
    'Add-LabMachineDefinition:MaxMemory' = 4GB
    'Add-LabMachineDefinition:Processors' = 4
    'Add-LabMachineDefinition:OperatingSystem' = $ServerOperatingSystem
}

# region Software dependencies

$DotNet8Desktop = (Get-ChildItem -Path "$labSources\SoftwarePackages" -Filter "windowsdesktop-runtime-8.*-win-x64.exe" | Sort-Object -Property Name -Descending | Select-Object -First 1).FullName

if ($null -eq $DotNet8Desktop) {

    Write-Error -Message "Required Software Packages not found. Aborting!" -ErrorAction Stop
}

#endregion

Add-LabDomainDefinition -Name $DomainFqdn -AdminUser Administrator -AdminPassword ($Password | ConvertFrom-SecureString -AsPlainText)
Set-LabInstallationCredential -Username Administrator -Password ($Password | ConvertFrom-SecureString -AsPlainText)
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace $AddressSpace

Add-LabMachineDefinition -Name $DomainController -Roles RootDC,CaRoot

Install-Lab

#region Configure networking

if ($Nat.IsPresent) {
    # Enable NAT on the Host for this Lab
    New-NetNat -Name "Nat-Switch-$LabName" -InternalIPInterfaceAddressPrefix $AddressSpace
}

Invoke-LabCommand -ActivityName 'Configuring networking' -ComputerName $DomainController -ScriptBlock {

    $HostAddress = $args[0]

    New-NetRoute -InterfaceIndex $((Get-NetAdapter | Select-Object -First 1).ifIndex) -NextHop $HostAddress -DestinationPrefix 0.0.0.0/0

    Add-DnsServerForwarder -IPAddress 8.8.8.8
    Add-DnsServerForwarder -IPAddress 8.8.4.4

} -ArgumentList $HostAddress

#endregion

#region Set up Lab Environment

Install-LabSoftwarePackage -ComputerName $DomainController -Path $DotNet8Desktop -CommandLine "/install /passive /norestart"

Copy-LabFileItem -Path "$labsources\SoftwarePackages\TameMyCerts" -ComputerName $(Get-LabVM -All) -DestinationFolderPath "C:\INSTALL"

Invoke-LabCommand -ActivityName 'Setting up Lab Environment' -ComputerName $DomainController -ScriptBlock {

    $VerbosePreference = "Continue"

    $DomainFqdn = $args[0]
    $Fqdn = [System.Net.Dns]::GetHostByName($env:computerName).HostName
    $ConfigString = "$Fqdn\LabRootCA1"

    . C:\INSTALL\TameMyCerts\Functions\Enable-Templatesynchronization.ps1
    . C:\INSTALL\TameMyCerts\Functions\Grant-CertificateTemplatePermission.ps1
    . C:\INSTALL\TameMyCerts\Functions\Import-CertificateTemplate.ps1
    . C:\INSTALL\TameMyCerts\Functions\Invoke-AutoEnrollmentTask.ps1
    . C:\INSTALL\TameMyCerts\Functions\Test-AdcsAvailability.ps1
    . C:\INSTALL\TameMyCerts\Functions\Get-OnlineCertificate.ps1

    #region Configure for Offline Environment

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "CertificateRevocation" -Type DWord -Value 0

    #endregion

    #region Configure Domain Environment

    Import-Module -Name ActiveDirectory

    $DomainName = $(Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain).DistinguishedName
    
    Write-Verbose -Message "Provisioning users and groups"
    
    New-ADOrganizationalUnit -Name "TameMyCerts Users" -Path $DomainName -ProtectedFromAccidentalDeletion $True
    New-ADOrganizationalUnit -Name "TameMyCerts Groups" -Path $DomainName -ProtectedFromAccidentalDeletion $True

    # The user doesnt really matter as this is a throw-away lab
    Add-Type -AssemblyName System.Web

    $Password = [System.Web.Security.Membership]::GeneratePassword(16,0) | ConvertTo-SecureString -AsPlainText -Force
    
    (1..7) | ForEach-Object -Process {
    
        New-ADUser `
            -SamAccountName "TestUser$($_)" `
            -UserPrincipalName "testuser$($_)@$DomainFqdn" `
            -Name "Test User $($_)" `
            -GivenName "Test" `
            -Surname "User $($_)" `
            -Path "OU=TameMyCerts Users,$DomainName" `
            -Enabled $True `
            -AccountPassword $Password
    
    }

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
    
    Get-ADUser Administrator | Set-ADUser -UserPrincipalName "Administrator@$DomainFqdn"
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

    #region configure CA
    
    & certutil -setreg CA\LogLevel 4
    & certutil -setreg CA\ValidityPeriodUnits 10
    
    & certutil -setreg Policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
    & certutil -setreg Policy\EditFlags +EDITF_ATTRIBUTEENDDATE
    & certutil -setreg CA\CRLFlags +CRLF_ALLOW_REQUEST_ATTRIBUTE_SUBJECT
    
    & certutil -setreg CA\SubjectTemplate +Title
    & certutil -setreg CA\SubjectTemplate +GivenName
    & certutil -setreg CA\SubjectTemplate +Initials
    & certutil -setreg CA\SubjectTemplate +SurName
    & certutil -setreg CA\SubjectTemplate +StreetAddress
    & certutil -setreg CA\SubjectTemplate +UnstructuredName
    & certutil -setreg CA\SubjectTemplate +UnstructuredAddress
    & certutil -setreg CA\SubjectTemplate +DeviceSerialNumber

    Set-Location -Path Cert:\LocalMachine
    New-Item -Name YKROOT
    New-Item -Name YKCA

    Get-ChildItem -Path C:\INSTALL\YKROOT\*.cer | ForEach-Object -Process { certutil -addstore YKROOT $_.FullName }
    Get-ChildItem -Path C:\INSTALL\YKCA\*.cer | ForEach-Object -Process { certutil -addstore YKCA $_.FullName }

    #endregion
    
    #region Import Certificate Templates
    
    Write-Verbose -Message "Importing certificate templates"
    
    $Templates = Get-ChildItem -Path "C:\INSTALL\TameMyCerts\Tests\*.ldf" | 
        Select-Object -ExpandProperty Name | 
            ForEach-Object -Process { $_.Split(".")[0] }
    
    ForEach ($TemplateName in $Templates) {
    
        $FilePath = "C:\INSTALL\TameMyCerts\Tests\$TemplateName.ldf"
    
        # This is a special case
        if ($TemplateName -eq "SpecialChars") { $TemplateName = "SpecialChars_Üöäß/&|()." }
    
        Write-Verbose -Message "Importing $TemplateName"
    
        Import-CertificateTemplate -File $FilePath -TemplateName $TemplateName
        Grant-CertificateTemplatePermission -Name $TemplateName
    }
    
    Write-Verbose -Message "Updating caches"
    
    Stop-Service -Name CertSvc
    
    Enable-TemplateSynchronization -Scope User
    Enable-TemplateSynchronization -Scope Computer
    
    Invoke-AutoEnrollmentTask -Task UserTask -Wait
    Invoke-AutoEnrollmentTask -Task SystemTask -Wait
    
    Start-Service -Name CertSvc
    
    do {
        Start-Sleep -Seconds 1
    } while (-not (Test-AdcsAvailability -ConfigString $ConfigString))
    
    Import-Module -Name ADCSAdministration

    # Note that it seems the Computer template is queried by AutomatedLab, so we must keep it
    ADCSAdministration\Get-CATemplate | Where-Object { $_.Name -ne "Machine" } | Remove-CATemplate -Force
    
    # Publish all imported templates
    ForEach ($TemplateName in $Templates) {
    
        # This is a special case
        if ($TemplateName -eq "SpecialChars") { $TemplateName = "SpecialChars_Üöäß/&|()." }
    
        Write-Verbose -Message "Binding $TemplateName to CA"
        Add-CATemplate -Name $TemplateName -Force
    }
    
    # endregion
    
    #region Request Enrollment Aqent certificate
    
    Write-Verbose -Message "Requesting Enrollment Agent certificate"

    Get-OnlineCertificate -CertificateTemplate "TestLabEnrollmentAgent" -ConfigString $ConfigString

    #endregion

    #region Install PowerShell modules
    
    Write-Verbose -Message "Installing PowerShell Modules"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

    Install-Module -Name "PSCertificateEnrollment" -MinimumVersion 1.0.9 -Force
    Install-Module -Name "Pester" -Force -SkipPublisherCheck

    #endregion

    #region Install TameMyCerts

    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    C:\INSTALL\TameMyCerts\TameMyCerts\install.ps1 -PolicyDirectory "C:\INSTALL\TameMyCerts\Tests"

    #endregion

} -ArgumentList $DomainFqdn

#endregion

#region Optional: Install additional non-essential software packages

"VSCodeSetup-x64-*.exe" | ForEach-Object -Process {

    $Package = (Get-ChildItem -Path "$labsources\SoftwarePackages" -Filter $_ | Sort-Object -Property Name -Descending | Select-Object -First 1).FullName
    if ($null -ne $Package) {
        Install-LabSoftwarePackage -ComputerName $(Get-LabVM -All) -Path $Package `
            -CommandLine "/VERYSILENT /mergetasks='!runcode,addcontextmenufiles,addcontextmenufolders,associatewithfiles,addtopath'" -AsJob

        Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

        # VS Code seems to start after installation regardless of parameter
        Invoke-LabCommand -ActivityName 'Kill VS Code processes' -ComputerName $(Get-LabVM -All) -ScriptBlock { Get-Process -Name Code | Stop-Process -Force }
    }
}

#endregion

Disable-LabAutoLogon -ComputerName (Get-LabVM -All)

Show-LabDeploymentSummary