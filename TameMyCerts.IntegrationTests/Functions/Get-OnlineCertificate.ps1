function Get-OnlineCertificate {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CertificateTemplate,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ConfigString,

        [switch]
        $MachineContext
    )

    begin {
        $BASE64 = 0x1
        $CR_IN_MACHINE = 0x100000
        $CR_DISP_ISSUED = 3
    }

    process {

        Write-Verbose -Message "Enrolling for $CertificateTemplate from $ConfigString"

        $CertEnroll = New-Object -ComObject X509Enrollment.CX509Enrollment
        $CertEnroll.InitializeFromTemplateName([bool]($MachineContext.IsPresent)+1, $CertificateTemplate)
        $CertificateRequest = $CertEnroll.CreateRequest($BASE64)

        $CertRequest = New-Object -ComObject CertificateAuthority.Request

        $Flags = $BASE64

        if ($MachineContext.IsPresent) {
            $Flags = $Flags -bor $CR_IN_MACHINE
        }

        $Status = $CertRequest.Submit($Flags, $CertificateRequest, [string]::Empty, $ConfigString)

        if ($Status -eq $CR_DISP_ISSUED) {

            $CertEnroll.InstallResponse(0, $CertRequest.GetCertificate($BASE64), $BASE64, [String]::Empty)

            $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $Certificate.Import([Convert]::FromBase64String($CertRequest.GetCertificate($BASE64)))
            $Certificate
        }
        else {

            Write-Error -Message (New-Object System.ComponentModel.Win32Exception($CertRequest.GetLastStatus())).Message
        }

        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertEnroll) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertRequest) | Out-Null
    }
}