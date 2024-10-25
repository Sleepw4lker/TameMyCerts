# Automated integration Tests for the TameMyCerts policy module

All a developer needs to do automatic integration testing for TameMyCerts with the [Pester](https://github.com/pester/Pester) PowerShell framework.

Tests are executed against a standardized lab environment. They leverage the [PSCertificateEnrollment](https://github.com/Sleepw4lker/PSCertificateEnrollment) PowerShell module.

High-level steps to get going are:

- Set up a Windows Server (2016, 2019 or 2022) virtual machine.
    - Ensure the machine is patched up to at least the May 2022 cumulative update so that the new SID extension is supported by ADCS.
    - Remember to set an administrator password strong enough for an AD deployment.
    - The [Windows Server 2022 Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022) ISO from Microsoft should do the job.
- Copy the content of the `TameMyCerts.IntegrationTests` folder from this repository into `C:\IntegrationTests\` on the lab machine.
- Deploy the environment with the scripts provided in the `Lab-Setup` directory.
    1. `New-Domain.ps1` (deploys an AD Domain and reboots the machine)
    2. `Configure-Lab.ps1` (populates AD with sample data, deploys the CA and creates certificate templates)
- Install the build of the TameMyCerts policy module you want to test. Set the policy directory (`-PolicyDirectory` switch) to `C:\IntegrationTests\Tests\` during installation.

After that you can run Pester (_...as Administrator_) with...

```powershell
Invoke-Pester -Output Detailed -Path C:\IntegrationTests\Tests\
```

## Known Issues

- If your Lab does not have interner access, install PSCertificateEnrollment and Pester PowerShell Modules manually.
- The `Lab-Setup.ps1` requests an Enrollment Agent certificate for the Administrator account, which fails sometimes. The certificate must be manually requested in that case.