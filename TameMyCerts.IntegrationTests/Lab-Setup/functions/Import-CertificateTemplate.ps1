#requires -Modules ActiveDirectory

function Import-CertificateTemplate {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ValidateScript({Test-Path -Path $_.FullName})]
        [ValidateScript({$_.Name.EndsWith(".ldf")})]
        [System.IO.FileInfo]
        $File,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TemplateName
    )

    begin {

        function New-TemplateOID {

            param([String]$ConfigNC)

            $ForestOid = Get-ADObject -Identity "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
                -Properties msPKI-Cert-Template-OID | Select-Object -ExpandProperty msPKI-Cert-Template-OID

            do {

                $OidSuffix1 = Get-Random -Minimum 1000000  -Maximum 99999999
                $OidSuffix2 = Get-Random -Minimum 10000000 -Maximum 99999999
                $Oid = "$ForestOid.$OidSuffix1.$OidSuffix2"

            } until (-not (Get-OidObject -ConfigNC $ConfigNC -Oid $Oid))

            return $Oid
        }

        function Get-OIDObject {

            param ([String]$Oid, [String]$ConfigNC )

            return Get-ADObject -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" -Filter {msPKI-Cert-Template-OID -eq $Oid}

        }

        $Ldifde = "$($env:SystemRoot)\System32\ldifde.exe"

        if (-not (Test-Path -Path $Ldifde)) {
            Write-Error -Message "$Ldifde not found! Run me on a DC!" -ErrorAction Stop
        }

        $ForestRootDomain = $(Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain).DistinguishedName
        $ConfigNC = "CN=Configuration,$ForestRootDomain"

    }

    process {

        if ($TemplateName -eq [String]::Empty) { $TemplateName = $File.Name.Split(".")[0]}

        $TemplatePath = "CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

        if (Test-Path -Path "AD:\$TemplatePath") {
            Write-Warning -Message "Skipping $TemplateName as it already exists!"
            return
        }

        $TempFile = "$env:Temp\$((New-Guid).Guid).ldf"

        (Get-Content -Path $File.FullName).Replace('{ConfigNC}', $ConfigNC) | Set-Content -Path $TempFile

        Write-Verbose -Message "Importing $TemplateName from $TempFile."

        [void](& $Ldifde -i -f $TempFile)

        Remove-Item -Path $TempFile

        $TemplateOid = New-TemplateOID -ConfigNC $ConfigNC
        Set-ADObject -Identity $TemplatePath -Replace @{"msPKI-Cert-Template-OID" = $TemplateOid}

        # This is a trick that will restore the msPKI-Enterprise-OID object which is linked to the pKICertificateTemplate object
        [void](& "$($env:SystemRoot)\System32\certutil.exe" -f -oid $TemplateOid $TemplateName)

        Get-OidObject -ConfigNC $ConfigNC -Oid $TemplateOid | Set-AdObject -Replace @{DisplayName = $TemplateName}
    }
}