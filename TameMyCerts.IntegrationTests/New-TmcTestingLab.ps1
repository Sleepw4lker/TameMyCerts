#requires -PSEdition Core

param(
    [Parameter(Mandatory=$True)]
    [SecureString]
    $Password
)

.\TmcTestingLab.ps1 -LabPrefix "2016" -AddressSpace "192.168.98.0/28"  -ServerOperatingSystem "Windows Server 2016 Standard Evaluation (Desktop Experience)" -Password $Password -Nat
.\TmcTestingLab.ps1 -LabPrefix "2019" -AddressSpace "192.168.98.16/28" -ServerOperatingSystem "Windows Server 2019 Standard Evaluation (Desktop Experience)" -Password $Password -Nat
.\TmcTestingLab.ps1 -LabPrefix "2022" -AddressSpace "192.168.98.32/28" -ServerOperatingSystem "Windows Server 2022 Standard Evaluation (Desktop Experience)" -Password $Password -Nat
.\TmcTestingLab.ps1 -LabPrefix "2025" -AddressSpace "192.168.98.48/28" -ServerOperatingSystem "Windows Server 2025 Standard Evaluation (Desktop Experience)" -Password $Password -Nat
