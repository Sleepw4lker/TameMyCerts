BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    Restart-Service -Name CertSvc

    do {
        Start-Sleep -Seconds 1
    } while (-not (Test-AdcsServiceAvailability))
}

Describe 'TameMyCerts.Tests' {

    It 'Given the module is installed, it is the active one' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules"
        $Active = (Get-ItemProperty -Path $RegistryRoot -Name Active).Active
        $Active | Should -Be "TameMyCerts.Policy"
    }

    It 'Given the module is installed, it is successfully loaded' {

        $Events = Get-WinEvent -FilterHashtable @{
            Logname='Application'; ProviderName='TameMyCerts'; Id=1; StartTime=$TestStartTime
        } -ErrorAction SilentlyContinue

        $Events.Count | Should -Be 1
    }
}