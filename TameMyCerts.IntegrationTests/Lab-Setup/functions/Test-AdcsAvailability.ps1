function Test-AdcsAvailability {
    
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ConfigString
    )
    
    $CertRequest = New-Object -ComObject CertificateAuthority.Request
    
    try {
        [void]($CertRequest.GetCAProperty($ConfigString, 0x6, 0x0, 0x4, 0x0))
        return $true
    }
    catch {
        return $false
    }
    finally {
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertRequest) | Out-Null
    }
}