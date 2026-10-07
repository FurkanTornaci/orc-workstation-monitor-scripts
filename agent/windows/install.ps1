#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [string]$ConfigPath,
  [string]$ApiUrl,
  [string]$Hostname = $env:COMPUTERNAME,
  [string]$PythonPath,
  [switch]$HideUsername
)
$ErrorActionPreference = 'Stop'
$InstallDir = Join-Path $env:ProgramData 'StrathclydeWorkstationMonitor'
$TaskName = 'StrathclydeWorkstationMonitor'
$AgentSource = Split-Path $PSScriptRoot -Parent

function Protect-Directory([string]$Directory) {
  # SID literals work on non-English Windows. SYSTEM and Administrators only.
  $Acl = New-Object System.Security.AccessControl.DirectorySecurity
  $Acl.SetAccessRuleProtection($true, $false)
  foreach ($Sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $Identity = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
  }
  Set-Acl -LiteralPath $Directory -AclObject $Acl
}
function Invoke-Python([string]$Executable, [string[]]$Arguments) {
  & $Executable @Arguments
  if ($LASTEXITCODE -ne 0) { throw 'Python command failed. Check dependency availability or heartbeat connectivity.' }
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $TaskName
}
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Protect-Directory $InstallDir
if (-not $PythonPath) {
  $Candidate = Get-Command python.exe -ErrorAction SilentlyContinue
  $UserProfiles = Split-Path $env:USERPROFILE -Parent
  if ($Candidate -and $Candidate.Source -notlike '*WindowsApps*' -and $Candidate.Source -notlike "$UserProfiles\*") { $PythonPath = $Candidate.Source }
  if (-not $PythonPath -and (Get-Command py.exe -ErrorAction SilentlyContinue)) {
    $PythonPath = (& py.exe -3 -c 'import sys; print(sys.executable)' | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0 -or $PythonPath -like "$UserProfiles\*") { $PythonPath = $null }
  }
  if ($PythonPath) {
    & $PythonPath -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
    if ($LASTEXITCODE -ne 0) { $PythonPath = $null }
  }
  # A user-only Python on PATH must not hide an existing machine-level runtime.
  if (-not $PythonPath) {
    foreach ($RegistryRoot in @('HKLM:\SOFTWARE\Python\PythonCore', 'HKLM:\SOFTWARE\WOW6432Node\Python\PythonCore')) {
      foreach ($VersionKey in (Get-ChildItem -LiteralPath $RegistryRoot -ErrorAction SilentlyContinue | Sort-Object PSChildName -Descending)) {
        $InstallKey = Get-Item -LiteralPath (Join-Path $VersionKey.PSPath 'InstallPath') -ErrorAction SilentlyContinue
        if ($InstallKey) {
          $Runtime = Join-Path ([string]$InstallKey.GetValue('')) 'python.exe'
          if ((Test-Path -LiteralPath $Runtime -PathType Leaf) -and $Runtime -notlike "$UserProfiles\*") {
            & $Runtime -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
            if ($LASTEXITCODE -eq 0) { $PythonPath = $Runtime; break }
          }
        }
      }
      if ($PythonPath) { break }
    }
  }
}
if (-not $PythonPath) {
  if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { throw 'Install Python 3.10+ for all users, then rerun with -PythonPath C:\Path\python.exe. Python must be accessible to SYSTEM.' }
  & winget.exe install --id Python.Python.3.13 --exact --scope machine --silent --accept-source-agreements --accept-package-agreements
  if ($LASTEXITCODE -ne 0) { throw 'Python installation failed; use an institution-approved all-users Python installation' }
  $PythonPath = Join-Path $env:ProgramFiles 'Python313\python.exe'
}
Invoke-Python $PythonPath @('-c', 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"')
if ($PythonPath -like "$env:USERPROFILE\*") { throw 'Use an all-users Python installation accessible to SYSTEM, not a user-profile installation' }
$VenvDir = Join-Path $InstallDir 'venv'
if (-not (Test-Path (Join-Path $VenvDir 'Scripts\python.exe'))) { Invoke-Python $PythonPath @('-m', 'venv', $VenvDir) }
$AgentPython = Join-Path $VenvDir 'Scripts\python.exe'
Copy-Item (Join-Path $AgentSource 'workstation_agent.py') $InstallDir -Force
Copy-Item (Join-Path $AgentSource 'requirements.txt') $InstallDir -Force
Invoke-Python $AgentPython @('-m', 'pip', 'install', '--disable-pip-version-check', '-r', (Join-Path $InstallDir 'requirements.txt'))
$StoredConfig = Join-Path $InstallDir 'config.json'
if ($ConfigPath) {
  $Configuration = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
} else {
  if (-not $ApiUrl) { $ApiUrl = Read-Host 'HTTPS monitor origin (e.g. https://monitor.example.org)' }
  $Secret = Read-Host 'Per-machine API token (input hidden)' -AsSecureString
  $Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
  try { $Token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pointer) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer) }
  $Configuration = [pscustomobject]@{ api_url = $ApiUrl; hostname = $Hostname; api_token = $Token; heartbeat_seconds = 60; collect_username = (-not $HideUsername); allow_local_http = $false }
  $Token = $null
}
if ($Configuration.api_url -notmatch '^https://') { throw 'The workstation installer requires an HTTPS endpoint' }
$EnrollmentName = [string]$Configuration.hostname
if ($HideUsername) { $Configuration.collect_username = $false }
$Configuration | ConvertTo-Json | Set-Content -LiteralPath $StoredConfig -Encoding UTF8
$Configuration = $null
Protect-Directory $InstallDir
Get-ChildItem -LiteralPath $InstallDir -Force | ForEach-Object {
  & icacls.exe $_.FullName /reset /T /C | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Failed to secure installed files' }
}
New-Item -ItemType Directory -Path (Join-Path $InstallDir 'logs') -Force | Out-Null
$AgentPath = Join-Path $InstallDir 'workstation_agent.py'
$LogPath = Join-Path $InstallDir 'logs\agent.log'
$TaskArgs = "`"$AgentPath`" --config `"$StoredConfig`" --log-file `"$LogPath`""
$Action = New-ScheduledTaskAction -Execute $AgentPython -Argument $TaskArgs -WorkingDirectory $InstallDir
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description 'Outbound workstation availability heartbeats; no user content collected.' -Force | Out-Null
$TaskStarted = [DateTime]::UtcNow
Start-ScheduledTask -TaskName $TaskName
# Confirm the actual SYSTEM background process, not an administrator's test run.
$Deadline = (Get-Date).AddSeconds(90)
$Accepted = $false
do {
  Start-Sleep -Seconds 2
  if (Test-Path $LogPath) {
    $Recent = Get-Content -LiteralPath $LogPath -Tail 8
    foreach ($Line in $Recent) {
      if ($Line -match 'Heartbeat accepted at (\S+)') {
        if ([DateTimeOffset]::Parse($Matches[1]).UtcDateTime -ge $TaskStarted) { $Accepted = $true; break }
      }
    }
    if ($Accepted) { break }
  }
} while ((Get-Date) -lt $Deadline)
if (-not $Accepted) { throw "Task installed but first heartbeat was not confirmed. Inspect $LogPath and the Task Scheduler state. Check HTTPS, Access heartbeat bypass and token. Rerun installer after resolving." }
Write-Host "Installed and reporting as $EnrollmentName. Startup task runs automatically as SYSTEM."
Write-Host "Protected configuration and logs: $InstallDir"
