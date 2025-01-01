#requires -Modules ActiveDirectory

function Grant-CertificateTemplatePermission  {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[ \-_a-zA-Z0-9]{1,15}\\[ \-_a-zA-Z0-9]{1,15}\$?$')]
        [String]
        $Identity = "NT AUTHORITY\AUTHENTICATED USERS",

        [Parameter(Mandatory=$False)]
        [ValidateSet("Enroll","AutoEnroll")]
        [String[]]
        $Permission = "Enroll"
    )

    begin {

        $ForestRootDomain = $(Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain).DistinguishedName
        $ConfigNC = "CN=Configuration,$ForestRootDomain"
    }

    process {

        $Path = "CN=$Name,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

        $Acl = Get-ACL -Path "AD:\$Path" -ErrorAction Stop

        $Sid = (New-Object -TypeName System.Security.Principal.NTAccount($Identity)).Translate([System.Security.Principal.SecurityIdentifier])

        $Permission | ForEach-Object -Process {

            Write-Verbose -Message "Granting $_ permission to $Identity ($Sid) on $Path."

            switch ($_) {

                "Enroll" {

                    $Ace = New-Object -TypeName System.DirectoryServices.ExtendedRightAccessRule -ArgumentList @(
                        $Sid,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        [System.Guid]"0E10C968-78FB-11D2-90D4-00C04F79DC55"
                    )
                }

                "AutoEnroll" {

                    $Ace = New-Object -TypeName System.DirectoryServices.ExtendedRightAccessRule -ArgumentList @(
                        $Sid,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        [System.Guid]"A05B8CC2-17BC-4802-A710-E7C15AB866A2"
                    )
                }
            }

            $Acl.AddAccessRule($Ace)
        }

        Set-Acl -Path "AD:\$Path" -AclObject $Acl
    }
}