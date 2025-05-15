<#
    .SYNOPSIS
    Exports all certificate templates in an Active Directory Forest to LDIF files.
    Needs ldifde.exe, thus run it on a Domain Controller.
#>
#requires -Modules ActiveDirectory
[cmdletbinding()]
param (
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path -Path $_})]
    [String]
    $Path,

    [Parameter(Mandatory=$false)]
    [Switch]
    $Generalize
)

function Remove-InvalidFileNameChars {

    param([String]$Name)

    $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
    return ($Name -replace $re)
}

$Ldifde = "$($env:SystemRoot)\System32\ldifde.exe"

If (-not (Test-Path -Path $Ldifde)) {
    Write-Error -Message "$Ldifde not found! Run me on a DC!" -ErrorAction Stop
}

$ForestRootDomain = $(Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain).DistinguishedName
$ConfigNC = "CN=Configuration,$ForestRootDomain"

Get-ChildItem -Path "AD:\CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC" | ForEach-Object -Process {

    $Name = $_.name
    $DistinguishedName = $_.distinguishedName

    $FilePath = "$Path\$(Remove-InvalidFileNameChars -Name $Name).ldf"

    Write-Verbose -Message "Exporting $Name to $FilePath"

    Remove-Item -Path $FilePath -ErrorAction SilentlyContinue

    $Arguments = @(
        "-f"
        "$FilePath"
        "-d"
        $DistinguishedName
        "-p"
        "Base"
        "-o"
        "dSCorePropagationData,whenChanged,whenCreated,uSNCreated,uSNChanged,objectGuid,msPKI-Cert-Template-OID"
    )
    [void](& $Ldifde $Arguments)

    if ($Generalize.IsPresent) {
        (Get-Content -Path $FilePath -Raw).Replace("`r`n ", "").Replace($ConfigNC, '{ConfigNC}') | Set-Content -Path $FilePath
    }
}