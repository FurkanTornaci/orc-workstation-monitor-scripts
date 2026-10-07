#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('status', 'start', 'stop', 'restart', 'logs')][string]$Action = 'status')
$ErrorActionPreference = 'Stop'
$TaskName = 'StrathclydeWorkstationMonitor'
switch ($Action) {
  'status' { Get-ScheduledTask -TaskName $TaskName; Get-ScheduledTaskInfo -TaskName $TaskName }
  'start' { Start-ScheduledTask -TaskName $TaskName }
  'stop' { Stop-ScheduledTask -TaskName $TaskName }
  'restart' { Stop-ScheduledTask -TaskName $TaskName; Start-Sleep -Seconds 2; Start-ScheduledTask -TaskName $TaskName }
  'logs' { Get-Content (Join-Path $env:ProgramData 'StrathclydeWorkstationMonitor\logs\agent.log') -Tail 40 }
}
