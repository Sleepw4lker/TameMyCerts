function Enable-TemplateSynchronization {

    [cmdletbinding()]
    param(
        [ValidateSet("User","Computer")]
        [String]
        $Scope = "User"
    )

    if ($Scope -eq "User") {
        $RegKey = "HKCU:\Software\Policies\Microsoft\Cryptography\AutoEnrollment"
    }
    else {
        $RegKey = "HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment"
    }

    $AEPolicy = (Get-ItemProperty -Path $RegKey -Name AEPolicy -ErrorAction SilentlyContinue).AEPolicy

    if ($null -ne $AEPolicy) {
        $AEPolicy = $AEPolicy -bor 0x1
    }
    else {
        $AEPolicy = 0x1
    }

    New-Item -Path $RegKey -Force | Out-Null
    Set-ItemProperty -Path $RegKey -Name AEPolicy -Value $AEPolicy -Force

}