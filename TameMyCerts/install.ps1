<#
    .SYNOPSIS
    Install script für the TameMyCerts rpolicy module.
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
    [Parameter(
        ParameterSetName="Install",
        Mandatory=$True
        )]
    [String]
    $PolicyDirectory,

    [Parameter(
        ParameterSetName="Uninstall",
        Mandatory=$False
        )]
    [Switch]
    $Uninstall
)

begin {
    
    New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_2012 -Value 9200
    New-Variable -Option Constant -Name PolicyModuleName -Value "TameMyCerts"
    New-Variable -Option Constant -Name RegistryRoot -Value "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
    New-Variable -Option Constant -Name BaseDirectory -Value (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent)

    New-Variable -Option Constant -Name ENUM_ENTERPRISE_ROOTCA -Value 0
    New-Variable -Option Constant -Name ENUM_ENTERPRISE_SUBCA -Value 1
    New-Variable -Option Constant -Name ENUM_STANDALONE_ROOTCA -Value 3
    New-Variable -Option Constant -Name ENUM_STANDALONE_SUBCA -Value 4

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

            Copy-ItemProperty `
                -Path $Source `
                -Name $_ `
                -Destination $Destination
        }
    }
}

process {

    # Ensuring the Script will be run on a supported Operating System
    If ([int32](Get-WmiObject Win32_OperatingSystem).BuildNumber -lt $BUILD_NUMBER_WINDOWS_2012) {
        Write-Error -Message "This must be run on Windows Server 2012 or newer! Aborting."
        Return 
    }

    # Ensuring the Script will be run with Elevation
    If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error -Message "This must be run as Administrator! Aborting."
        Return
    }

    # We grab the relevant Data from the Registry
    If (-not (Test-Path -Path $RegistryRoot)) {
        Write-Error -Message "$($RegistryRoot) not found. Is this really a CA?"
        Return
    }

    # Prevent running the installer without the module present
    If (-not (Test-Path -Path "$BaseDirectory\$($PolicyModuleName).dll")) {
        Write-Error -Message "Could not find $BaseDirectory\$($PolicyModuleName).dll"
        Return
    }

    $CaName = (Get-ItemProperty -Path $RegistryRoot -Name Active).Active
    $CaType = (Get-ItemProperty -Path "$RegistryRoot\$($CaName)" -Name CaType -ErrorAction Stop).CaType
    $KeyStorageProvider = (Get-ItemProperty -Path "$($RegistryRoot)\$($CaName)\CSP" -Name Provider).Provider

    If (-not (($CaType -eq $ENUM_ENTERPRISE_ROOTCA) -or ($CaType -eq $ENUM_ENTERPRISE_SUBCA))) {
        Write-Error -Message "The $PolicyModuleName policy module currently does not support standalone certification authorities."
        Return
    }

    $DefaultPolicyModuleName = "CertificateAuthority_MicrosoftDefault.Policy"
    $RegistryHiveDefault = "$($RegistryRoot)\$($CaName)\PolicyModules\$DefaultPolicyModuleName"
    $RegistryHiveCustom = "$($RegistryRoot)\$($CaName)\PolicyModules\$($PolicyModuleName).Policy"

    # This part is called both on (re)installation and uninstallation
    Write-Verbose -Message "Stopping certification authority service"
    Stop-Service -Name certsvc

    If ($KeyStorageProvider -eq "SafeNet Key Storage Provider") {
        Write-Warning -Message "Waiting 120 seconds for the AD CS service to shutdown properly (to avoid known bug in SafeNet Key Storage Provider)."
        Start-Sleep -Seconds 120
    }

    $MmcProcesses = Get-Process -ProcessName "mmc" -ErrorAction SilentlyContinue
    
    If ($MmcProcesses) {
        Write-Warning -Message "Killing running MMC processes (certsrv.msc may lock the policy module DLL if opened during (un)installation)."
        $MmcProcesses | Stop-Process -Force
    }

    Write-Verbose -Message "Trying to unregister $PolicyModuleName policy module COM object"
    "System32","SysWOW64" | ForEach-Object -Process {

        $Path = "$($env:SystemRoot)\$($_)\$($PolicyModuleName).dll"

        If (Test-Path -Path $Path) {

            Start-Process `
                -FilePath "$($env:SystemRoot)\Microsoft.NET\Framework64\v4.0.30319\regasm.exe" `
                -ArgumentList "/unregister", $Path `
                -Wait `
                -WindowStyle Hidden
        }
    }

    Write-Verbose -Message "Deleting policy module DLL file"
    "System32","SysWOW64" | ForEach-Object -Process {

        $Path = "$($env:SystemRoot)\$($_)\$($PolicyModuleName).dll"

        If (Test-Path -Path $Path) {

            Remove-Item -Path $Path -Force
        }
    }
    
    # Uninstall
    If ($Uninstall.IsPresent) {

        If (Get-ItemProperty -Path $RegistryHiveCustom -Name PolicyDirectory -ErrorAction SilentlyContinue) {

            Write-Verbose "Deleting policy directory from registry"
            Remove-ItemProperty -Path $RegistryHiveCustom -Name PolicyDirectory

            Write-Verbose "Copying back configuration to default path (may have changed in the meantime)."
            Copy-Registry -Source $RegistryHiveCustom -Destination $RegistryHiveDefault

            Write-Verbose -Message "Deleting custom module configuration $RegistryHiveCustom from registry"
            Remove-Item -Path $RegistryHiveCustom -Recurse -Force
        }
        
        If ((Get-ItemProperty -Path "$($RegistryRoot)\$($CaName)\PolicyModules" -Name Active).Active -ne "$DefaultPolicyModuleName") {

            Write-Verbose "Setting the active policy module back to Microsoft Default policy module"
            Set-ItemProperty -Path "$($RegistryRoot)\$($CaName)\PolicyModules" -Name Active -Value "$DefaultPolicyModuleName"
        }
    }

    # (Re)Install
    If (-not $Uninstall.IsPresent) {

        Write-Verbose -Message "Registering $PolicyModuleName policy module COM Object"
        "System32","SysWOW64" | ForEach-Object -Process {

            $SourcePath = "$BaseDirectory\$($PolicyModuleName).dll"
            $Path = "$($env:SystemRoot)\$($_)\$($PolicyModuleName).dll"
    
            Copy-Item -Path $SourcePath -Destination $Path -Force -ErrorAction Stop

            Start-Process `
                -FilePath "$($env:SystemRoot)\Microsoft.NET\Framework64\v4.0.30319\regasm.exe" `
                -ArgumentList $Path `
                -Wait `
                -WindowStyle Hidden
        }

        If (-not (Test-Path -Path $RegistryHiveCustom)) {

            Write-Verbose -Message "Creating registry path"
            [void](New-Item -Path "$($RegistryRoot)\$($CaName)\PolicyModules" -Name "$($PolicyModuleName).Policy" -Force)

            Write-Verbose -Message "Copying registry Keys from Microsoft Default Policy module to $RegistryHiveCustom"
            Copy-Registry -Source $RegistryHiveDefault -Destination $RegistryHiveCustom
        }
        
        Write-Verbose -Message "Setting policy directory in registry"
        [void](Set-ItemProperty -Path $RegistryHiveCustom -Name PolicyDirectory -Value $PolicyDirectory -Force)

        Write-Verbose -Message "Setting the currently active policy Module to $PolicyModuleName"
        Set-ItemProperty -Path "$($RegistryRoot)\$($CaName)\PolicyModules" -Name Active -Value "$($PolicyModuleName).Policy" -Force

        If ([System.Diagnostics.EventLog]::SourceExists($PolicyModuleName) -eq $false) {
            Write-Verbose -Message "Registering Windows event source ""$PolicyModuleName"""
            [System.Diagnostics.EventLog]::CreateEventSource("$PolicyModuleName", 'Application')
        }
    }

    Write-Verbose -Message "Starting certification authority service"
    Start-Service -Name certsvc

    [PSCustomObject]@{
        Success = $True
        Message = "The operation was successful."
    }
}

end {}