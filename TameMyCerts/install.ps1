#requires -PSEdition Desktop -Version 5.1 
<#
    .SYNOPSIS
    Install script for the TameMyCerts policy module.
    Installs the module, configures the registry and activates the module.

    .PARAMETER PolicyDirectory
    Installs the module and configures it to use the specified directory for policy definition.
    Also call this for updates or reinstalations.

    .PARAMETER Uninstall
    Call this if you want to uninstall the module.
#>
[cmdletbinding()]
param(
    [ValidateScript({Test-Path -Path $_})]
    [Parameter(ParameterSetName="Install", Mandatory=$True)]
    [String]
    $PolicyDirectory,

    [Parameter(ParameterSetName="Uninstall", Mandatory=$True)]
    [Switch]
    $Uninstall
)

$ErrorActionPreference = $Stop

function Copy-Registry {

    [cmdletbinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_})]
        [String]
        $Source,

        [ValidateNotNullOrEmpty()]
        [String]
        $Destination
    )
    
    (Get-Item -Path $Source).Property | ForEach-Object -Process {

        Copy-ItemProperty -Path $Source -Name $_ -Destination $Destination
    }
}

New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_2016 -Value 14393
New-Variable -Option Constant -Name PolicyModuleName -Value "TameMyCerts"
New-Variable -Option Constant -Name CaRegistryRoot -Value "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
New-Variable -Option Constant -Name BaseDirectory -Value (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent)
New-Variable -Option Constant -Name AppInstallDirectory -Value "$env:ProgramFiles\TameMyCerts"
New-Variable -Option Constant -Name ENUM_ENTERPRISE_ROOTCA -Value 0
New-Variable -Option Constant -Name ENUM_ENTERPRISE_SUBCA -Value 1
New-Variable -Option Constant -Name DefaultPolicyModuleName -Value "CertificateAuthority_MicrosoftDefault.Policy"
New-Variable -Option Constant -Name FileList -Value @(
    "CERTCLILIB.dll",
    "CERTPOLICYLIB.dll",
    "System.Diagnostics.EventLog.dll",
    "System.DirectoryServices.dll",
    "TameMyCerts.comhost.dll",
    "TameMyCerts.deps.json",
    "TameMyCerts.dll",
    "TameMyCerts.Events.dll",
    "TameMyCerts.Events.man",
    "TameMyCerts.runtimeconfig.json",
    "runtimes\win\lib\net8.0\System.Diagnostics.EventLog.dll",
    "runtimes\win\lib\net8.0\System.Diagnostics.EventLog.Messages.dll",
    "runtimes\win\lib\net8.0\System.DirectoryServices.dll"
)

# Ensuring the Script will be run with Elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error -Message "This must be run as Administrator! Aborting." -ErrorAction Stop
}

# Ensuring the Script will be run on a supported Operating System
if ([int32](Get-WmiObject Win32_OperatingSystem).BuildNumber -lt $BUILD_NUMBER_WINDOWS_2016) {
    Write-Error -Message "This must be run on Windows Server 2016 or newer! Aborting." -ErrorAction Stop
}

# Ensuring a certification authority is installed
if (-not (Test-Path -Path $CaRegistryRoot)) {
    Write-Error -Message "$($CaRegistryRoot) not found. Is a certification authority installed?" -ErrorAction Stop
}

# Ensuring all required files are present
$FileList | ForEach-Object -Process {

    if (-not (Test-Path -Path "$BaseDirectory\$_")) {
        Write-Error -Message "Could not find $_, aborting!" -ErrorAction Stop
    }
}

# Ensuring that software prerequisites are met
if ((Get-Command -Name dotnet -ErrorAction SilentlyContinue).Version.Major -ne 8) {
    Write-Error -Message ".NET 8 Runtime is not installed! Aborting." -ErrorAction Stop
}

$CaName = (Get-ItemProperty -Path $CaRegistryRoot -Name Active).Active
$CaType = (Get-ItemProperty -Path "$CaRegistryRoot\$($CaName)" -Name CaType -ErrorAction Stop).CaType

if (-not (($CaType -eq $ENUM_ENTERPRISE_ROOTCA) -or ($CaType -eq $ENUM_ENTERPRISE_SUBCA))) {
    Write-Error -Message "The $PolicyModuleName policy module does not support standalone certification authorities." -ErrorAction Stop
}

$RegistryHiveDefault = "$($CaRegistryRoot)\$($CaName)\PolicyModules\$DefaultPolicyModuleName"
$RegistryHiveCustom = "$($CaRegistryRoot)\$($CaName)\PolicyModules\$($PolicyModuleName).Policy"

#region This part is called both on (re)installation and uninstallation

Write-Verbose -Message "Stopping certification authority service"
Stop-Service -Name certsvc

# Workaround for Safenet KSP
if ((Get-ItemProperty -Path "$($CaRegistryRoot)\$($CaName)\CSP" -Name Provider).Provider -eq "SafeNet Key Storage Provider") {
    Write-Warning -Message "Waiting 120 seconds for the AD CS service to shutdown properly (to avoid known bug in SafeNet Key Storage Provider)."
    Start-Sleep -Seconds 120
}

$MmcProcesses = Get-Process -ProcessName "mmc" -ErrorAction SilentlyContinue

if ($MmcProcesses) {
    Write-Warning -Message "Killing running MMC processes (certsrv.msc may lock the policy module DLL if opened during (un)installation)."
    $MmcProcesses | Stop-Process -Force
}

"System32","SysWOW64" | ForEach-Object -Process {

    $Path = "$($env:SystemRoot)\$($_)\$($PolicyModuleName).dll"

    If (Test-Path -Path $Path) {

        Write-Verbose -Message "Unregistering $PolicyModuleName (legacy) policy module COM object"

        Start-Process `
            -FilePath "$($env:SystemRoot)\Microsoft.NET\Framework64\v4.0.30319\regasm.exe" `
            -ArgumentList "/unregister", $Path `
            -Wait `
            -WindowStyle Hidden

        Write-Verbose -Message "Deleting (legacy) policy module DLL file ($Path)"
        Remove-Item -Path $Path -Force
    }
}

if (Test-Path -Path "$AppInstallDirectory\TameMyCerts.comhost.dll") {

    Write-Verbose -Message "Unregistering $PolicyModuleName policy module COM object"

    Start-Process `
        -FilePath "$($env:SystemRoot)\System32\regsvr32.exe" `
        -ArgumentList "/s", "/u", """$AppInstallDirectory\TameMyCerts.comhost.dll""" `
        -Wait `
        -WindowStyle Hidden
}

# Find a few older and unregister those.
if ($null -ne (Get-WinEvent -ListProvider "TameMyCerts-TameMyCerts-Policy" -ErrorAction SilentlyContinue)) { 

    Write-Verbose -Message "Removing the EventProvider TameMyCerts-TameMyCerts-Policy"

    $tempfile = [System.IO.Path]::GetTempFileName()

    $xmlcontent = @'
<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
<instrumentation xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events">
<events xmlns="http://schemas.microsoft.com/win/2004/08/events">
<provider name="TameMyCerts-TameMyCerts-Policy" guid="{01e38251-e8f1-5aea-594c-12c672505ecf}" resourceFileName="TameMyCerts.Events.dll" messageFileName="TameMyCerts.Events.dll" symbol="TameMyCertsTameMyCertsPolicy">
</provider>
</events>
</instrumentation>
</instrumentationManifest>
'@
    Set-Content -Path $tempfile -Value $xmlcontent

    Start-Process `
        -FilePath "$($env:SystemRoot)\System32\wevtutil.exe" `
        -ArgumentList "um", """$tempfile""" `
        -Wait `
        -WindowStyle Hidden

    Remove-Item $tempfile
}

if ($null -ne (Get-WinEvent -ListProvider "TameMyCerts" -ErrorAction SilentlyContinue)) { 

    Write-Verbose "Removing the EventProvider TameMyCerts"

    $tempfile = [System.IO.Path]::GetTempFileName()
    $xmlcontent = @'
<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
<instrumentation xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events">
<events xmlns="http://schemas.microsoft.com/win/2004/08/events">
<provider name="TameMyCerts" guid="{5ab879f8-8136-5440-4d8c-3d0ac8846520}" resourceFileName="TameMyCerts.Events.dll" messageFileName="TameMyCerts.Events.dll" symbol="TameMyCerts">
</provider>
</events>
</instrumentation>
</instrumentationManifest>
'@
    Set-Content -Path $tempfile -Value $xmlcontent

    Start-Process `
        -FilePath "$($env:SystemRoot)\System32\wevtutil.exe" `
        -ArgumentList "um", """$tempfile""" `
        -Wait `
        -WindowStyle Hidden

    Remove-Item $tempfile
}

Write-Verbose -Message "Deleting Application directory $AppInstallDirectory"
Remove-Item -Path $AppInstallDirectory -Recurse -Force -ErrorAction SilentlyContinue

#endregion

#region Uninstall

if ($Uninstall.IsPresent) {

    if (Get-ItemProperty -Path $RegistryHiveCustom -Name PolicyDirectory -ErrorAction SilentlyContinue) {

        Write-Verbose "Deleting custom entries from Policy Module from registry"
        Remove-ItemProperty -Path $RegistryHiveCustom -Name PolicyDirectory -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $RegistryHiveCustom -Name TmcFlags -ErrorAction SilentlyContinue

        Write-Verbose "Copying back configuration to default path (may have changed in the meantime)."
        Copy-Registry -Source $RegistryHiveCustom -Destination $RegistryHiveDefault

        Write-Verbose -Message "Deleting custom module configuration $RegistryHiveCustom from registry"
        Remove-Item -Path $RegistryHiveCustom -Recurse -Force
    }
    
    if ((Get-ItemProperty -Path "$($CaRegistryRoot)\$($CaName)\PolicyModules" -Name Active).Active -ne "$DefaultPolicyModuleName") {

        Write-Verbose "Setting the active policy module back to Microsoft Default policy module"
        Set-ItemProperty -Path "$($CaRegistryRoot)\$($CaName)\PolicyModules" -Name Active -Value "$DefaultPolicyModuleName"
    }

    if ([System.Diagnostics.EventLog]::SourceExists($PolicyModuleName) -eq $true) {
        Write-Verbose -Message "Deleting Windows event source ""$PolicyModuleName"""
        [System.Diagnostics.EventLog]::DeleteEventSource($PolicyModuleName)
    }
}

#endregion

#region (Re)Install

if (-not $Uninstall.IsPresent) {

    Write-Verbose -Message "Creating Application directory $AppInstallDirectory"
    New-Item -Path $AppInstallDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path "$AppInstallDirectory\\runtimes\win\lib\net8.0" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    
    # Only copy the files if .\install.ps1 is run from another folder than the AppInstallDirectory
    if ($BaseDirectory -ne $AppInstallDirectory)
    {
        $FileList | ForEach-Object -Process {

            Write-Verbose -Message "Copying $_ to $AppInstallDirectory."

            Copy-Item -Path "$BaseDirectory\$_" -Destination "$AppInstallDirectory\$_" -Force
        }
    }

    Write-Verbose -Message "Registering $PolicyModuleName policy module COM Object"

    Start-Process `
        -FilePath "$($env:SystemRoot)\System32\regsvr32.exe" `
        -ArgumentList "/s", """$AppInstallDirectory\TameMyCerts.comhost.dll""" `
        -Wait `
        -WindowStyle Hidden

    if (-not (Test-Path -Path $RegistryHiveCustom)) {

        Write-Verbose -Message "Creating registry path"
        [void](New-Item -Path "$($CaRegistryRoot)\$($CaName)\PolicyModules" -Name "$($PolicyModuleName).Policy" -Force)

        Write-Verbose -Message "Copying registry Keys from Microsoft Default policy module to $RegistryHiveCustom"
        Copy-Registry -Source $RegistryHiveDefault -Destination $RegistryHiveCustom
    }
    
    Write-Verbose -Message "Setting policy directory in registry"
    [void](Set-ItemProperty -Path $RegistryHiveCustom -Name PolicyDirectory -Value $PolicyDirectory -Force)

    Write-Verbose -Message "Setting the currently active policy Module to $PolicyModuleName"
    Set-ItemProperty -Path "$($CaRegistryRoot)\$($CaName)\PolicyModules" -Name Active -Value "$($PolicyModuleName).Policy" -Force

    if ([System.Diagnostics.EventLog]::SourceExists($PolicyModuleName) -eq $false) {
        Write-Verbose -Message "Registering Windows event source ""$PolicyModuleName"""
        [System.Diagnostics.EventLog]::CreateEventSource($PolicyModuleName, "Application")
    }

    # if ETW Logging manifest exist register that one.
    if ((Test-Path -Path "$AppInstallDirectory\$($PolicyModuleName).Events.dll") -and (Test-Path -Path "$AppInstallDirectory\$($PolicyModuleName).Events.man")) {

        Write-Verbose "Registering the EventProvider TameMyCerts-TameMyCerts-Policy"

        Start-Process `
            -FilePath "$($env:SystemRoot)\System32\wevtutil.exe" `
            -ArgumentList "im", """$AppInstallDirectory\$($PolicyModuleName).events.man""","/resourceFilePath:""$AppInstallDirectory\$($PolicyModuleName).events.dll""", "/messageFilePath:""$AppInstallDirectory\$($PolicyModuleName).events.dll""" `
            -Wait `
            -WindowStyle Hidden
    }
}

#endregion

Write-Verbose -Message "Starting certification authority service"
Start-Service -Name certsvc

[PSCustomObject]@{
    Success = $True
    Message = "The operation was successful."
}