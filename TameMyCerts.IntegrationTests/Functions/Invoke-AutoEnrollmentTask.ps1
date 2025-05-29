function Invoke-AutoEnrollmentTask {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("UserTask", "SystemTask")]
        [string]
        $Task = "UserTask",

        [Parameter(Mandatory=$false)]
        [switch]
        $Wait
    )

    New-Variable -Option Constant -Name TaskRunFlags -Value @{
        TASK_RUN_NO_FLAGS = 0
        TASK_RUN_AS_SELF = 1
        TASK_RUN_IGNORE_CONSTRAINTS = 2
        TASK_RUN_USE_SESSION_ID = 3
        TASK_RUN_USER_SID = 4
    }

    if ($Task -eq "UserTask") {
        $Flags = $TaskRunFlags.TASK_RUN_AS_SELF
    }
    else {
        $Flags = $TaskRunFlags.TASK_RUN_NO_FLAGS
    }

    $TaskScheduler = New-Object -ComObject "Schedule.Service"
    $TaskScheduler.Connect()
    $UserTask = $TaskScheduler.GetFolder("Microsoft\Windows\CertificateServicesClient").GetTask($Task)
    $UserTask.RunEx($null, $Flags, 0, $null) | Out-Null

    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($TaskScheduler) | Out-Null

    if ($Wait.IsPresent) {
        do {
            Start-Sleep -Seconds 1
        } while ((Get-ScheduledTask -TaskPath \Microsoft\Windows\CertificateServicesClient\ -TaskName $Task).PSBase.CimInstanceProperties['State'].Value -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Running)
    }
}