<#
    .SYNOPSIS
    Exports all certificate templates bound to our test certification authority to LDIF files.
#>

#Requires -Modules ADCSAdministration

[cmdletbinding()]
param (
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ConfigNC = "CN=Configuration,DC=tamemycerts-tests,DC=local"
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

Function Remove-InvalidFileNameChars {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Name
    )

    process {

        $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
        $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
        return ($Name -replace $re)

    }
}

Get-CATemplate | ForEach-Object -Process {

    $FilePath = "$(Remove-InvalidFileNameChars -Name $_.Name).ldf"

    Remove-Item -Path $FilePath -ErrorAction SilentlyContinue

    $Arguments = @(
        "-f"
        "$FilePath"
        "-d"
        "CN=$($_.Name),CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
        "-p"
        "Base"
        "-o"
        "dSCorePropagationData,whenChanged,whenCreated,uSNCreated,uSNChanged,objectGuid,msPKI-Cert-Template-OID"
    )
    [void](& ldifde $Arguments)
}