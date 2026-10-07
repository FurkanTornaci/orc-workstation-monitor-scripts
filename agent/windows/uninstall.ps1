#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$TaskName = 'StrathclydeWorkstationMonitor'
$InstallDir = Join-Path $env:ProgramData 'StrathclydeWorkstationMonitor'
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $TaskName
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
Write-Host 'Agent, task, configuration and logs removed. Shared system Python remains installed.'
Write-Host 'Revoke this machine token centrally using npm run machine -- revoke --remote --hostname COMPUTERNAME.'
