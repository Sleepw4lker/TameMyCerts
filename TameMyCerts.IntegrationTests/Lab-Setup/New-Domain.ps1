<#
    .SYNOPSIS
    Installs the Active Directory Domain necessary for the automated integration tests.
#>

#Requires -Modules ServerManager

[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $DomainName = "tamemycerts-tests.local",

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $DomainNetbiosName = "TAMEMYCERTS"
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

# TODO: Maybe we want to convert a DHCP address into a fixed one here
# TODO: Set static IP when NIC doesnt have a DHCP address (for offline deployments)

[void](Install-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools)

# The DS restore password doesnt really matter as this is a throw-away lab
Add-Type -AssemblyName System.Web
$Password = [System.Web.Security.Membership]::GeneratePassword(16,0) | ConvertTo-SecureString -AsPlainText -Force

$ForestProperties = @{

    DomainName = $DomainName
    DomainNetbiosName = $DomainNetbiosName
    SafeModeAdministratorPassword = $Password
    ForestMode = "WinThreshold"
    DomainMode = "WinThreshold"
    CreateDnsDelegation = $False
    InstallDns = $True
    DatabasePath = "$env:SystemRoot\NTDS"
    LogPath = "$env:SystemRoot\NTDS"
    SysvolPath = "$env:SystemRoot\SYSVOL"
    NoRebootOnCompletion = $False
    Force = $True

}

Import-Module ADDSDeployment

[void](Install-ADDSForest @ForestProperties)