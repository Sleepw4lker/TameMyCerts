function Test-AdcsAvailability {
    
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ConfigString
    )

    $CertAdmin = New-Object -ComObject CertificateAuthority.Admin.1

    try {
        [void]($CertAdmin.GetCAProperty($ConfigString, 0x6, 0x0, 0x4, 0x0))
        return $true
    }
    catch {
        return $false
    }
    finally {
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertAdmin) | Out-Null
    }
}