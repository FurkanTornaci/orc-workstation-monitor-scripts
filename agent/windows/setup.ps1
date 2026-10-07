#Requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$BundleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$ConfigPath = Join-Path $BundleRoot 'config.json'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
$IsAdministrator = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$ExitCode = 1
try {
  if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw 'config.json is missing. Extract the entire workstation setup ZIP into a folder, then open Install.cmd in that folder.'
  }
  if (-not $IsAdministrator) {
    # Only paths are passed to the elevated process; the machine token stays in its file.
    $Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
    $Process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $Arguments -Verb RunAs -Wait -PassThru
    exit $Process.ExitCode
  }
  Write-Host 'Installing Workstation Monitor. This can take a few minutes.'
  & (Join-Path $PSScriptRoot 'install.ps1') -ConfigPath $ConfigPath
  $ExitCode = 0
  Write-Host ''
  Write-Host 'Setup complete. Check this workstation in the dashboard.' -ForegroundColor Green
  Write-Host 'You can now delete the downloaded ZIP and extracted setup folder.'
} catch {
  Write-Host "Setup could not finish: $($_.Exception.Message)" -ForegroundColor Red
}
if ($IsAdministrator) { Read-Host 'Press Enter to close' | Out-Null }
exit $ExitCode
