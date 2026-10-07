#Requires -Version 5.1
# Run the configuration/preflight contract without installing software or a task.
$ErrorActionPreference = 'Stop'
$WindowsSource = Join-Path (Split-Path $PSScriptRoot -Parent) 'windows'
. (Join-Path $WindowsSource 'configuration.ps1')
$global:WorkstationTestAssertions = 0

function Assert-Condition([bool]$Condition, [string]$Message) {
  if (-not $Condition) { throw $Message }
  $global:WorkstationTestAssertions += 1
}
function Assert-Rejected([scriptblock]$Operation, [string]$MessagePart, [string]$Secret) {
  $Failure = $null
  try { & $Operation | Out-Null } catch { $Failure = $_ }
  Assert-Condition ($null -ne $Failure) 'Invalid input was accepted.'
  Assert-Condition ($Failure.Exception.Message.Contains($MessagePart)) 'Unexpected validation failure.'
  if ($Secret) {
    Assert-Condition (-not $Failure.ToString().Contains($Secret)) 'A validation error exposed the API key.'
  }
}

$TestDirectory = Join-Path ([IO.Path]::GetTempPath()) ('monitor-config-test-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($TestDirectory)
$PreviousComputerName = $env:COMPUTERNAME
$PreviousProgramData = $env:ProgramData
$SyntheticKey = ('abcDEF012_-' * 4)
$SecureKey = ConvertTo-SecureString $SyntheticKey -AsPlainText -Force
$script:PromptCount = 0

# A supplied key must never trigger another prompt. The prompt path is tested too.
function Read-Host {
  param([string]$Prompt, [switch]$AsSecureString)
  Assert-Condition $AsSecureString 'Key input was not hidden.'
  $script:PromptCount += 1
  return $SecureKey
}

try {
  $env:COMPUTERNAME = 'IT-TEST-PC'
  $env:ProgramData = $TestDirectory
  $Configuration = Resolve-WorkstationConfiguration -ApiKey $SecureKey
  Assert-Condition ($Configuration.hostname -eq 'IT-TEST-PC') 'Device name was not detected automatically.'
  Assert-Condition ($Configuration.api_url -eq 'https://strathclyde-workstation-monitor.furkantornaci.workers.dev') 'The default monitor address is incorrect.'
  Assert-Condition ($Configuration.api_token -ceq $SyntheticKey) 'The supplied key was changed.'
  Assert-Condition ($Configuration.heartbeat_seconds -eq 60) 'The update interval is incorrect.'
  Assert-Condition ($Configuration.collect_username -eq $true) 'The normal username setting changed.'
  Assert-Condition ($Configuration.allow_local_http -eq $false) 'HTTP was enabled.'
  Assert-Condition ($script:PromptCount -eq 0) 'Supplying an API key triggered a prompt.'
  $Hidden = Resolve-WorkstationConfiguration -ApiKey $SecureKey -HideUsername
  Assert-Condition ($Hidden.collect_username -eq $false) 'Username suppression failed.'
  $Custom = Resolve-WorkstationConfiguration -ApiKey $SecureKey -ApiUrl 'https://monitor.example.org/' -Hostname 'custom-pc'
  Assert-Condition ($Custom.api_url -eq 'https://monitor.example.org') 'Origin normalisation failed.'
  Assert-Condition ($Custom.hostname -eq 'CUSTOM-PC') 'The hostname override was not normalised.'
  $Prompted = Resolve-WorkstationConfiguration
  Assert-Condition ($script:PromptCount -eq 1) 'The interactive installer did not ask for exactly one key.'
  Assert-Condition ($Prompted.api_token -ceq $SyntheticKey) 'Hidden input was not used.'

  $EmptyKey = New-Object Security.SecureString
  Assert-Rejected { Resolve-WorkstationConfiguration -ApiKey $EmptyKey } 'API key is required' ''
  Assert-Rejected { Resolve-WorkstationConfiguration -ApiKey $null } 'API key is required' ''
  $ShortKey = ConvertTo-SecureString 'invalid-short-key' -AsPlainText -Force
  Assert-Rejected { Resolve-WorkstationConfiguration -ApiKey $ShortKey } 'valid provisioned' 'invalid-short-key'
  $PlaceholderKey = ConvertTo-SecureString ('REPLACE_' + ('x' * 43)) -AsPlainText -Force
  Assert-Rejected { Resolve-WorkstationConfiguration -ApiKey $PlaceholderKey } 'valid provisioned' ('REPLACE_' + ('x' * 43))
  foreach ($BadUrl in @('http://monitor.example.org', 'https://user:pass@monitor.example.org', 'https://monitor.example.org/api/heartbeat', 'https://monitor.example.org?key=test', 'https://monitor.example.org#fragment', 'not-a-url')) {
    Assert-Rejected { Resolve-WorkstationConfiguration -ApiKey $SecureKey -ApiUrl $BadUrl } 'HTTPS server origin' $SyntheticKey
  }
  Assert-Rejected { Resolve-WorkstationConfiguration -ApiKey $SecureKey -Hostname 'bad/name' } 'device name' $SyntheticKey

  $ConfigPath = Join-Path $TestDirectory 'config.json'
  $PrivateConfig = @{
    api_url = 'https://monitor.example.org'
    hostname = 'label-pc'
    api_token = $SyntheticKey
    heartbeat_seconds = 45
    collect_username = $true
    allow_local_http = $false
  }
  $PrivateConfig | ConvertTo-Json | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
  $FromFile = Resolve-WorkstationConfiguration -ConfigPath $ConfigPath -HideUsername
  Assert-Condition ($FromFile.hostname -eq 'LABEL-PC') 'Prepared configuration compatibility failed.'
  Assert-Condition ($FromFile.api_token -ceq $SyntheticKey) 'A private configuration key was changed.'
  Assert-Condition ($FromFile.collect_username -eq $false) 'A private configuration ignored HideUsername.'
  Assert-Condition ($FromFile.heartbeat_seconds -eq 45) 'A private configuration interval was changed.'
  foreach ($InvalidInterval in @($true, '60', 29, 121)) {
    $PrivateConfig.heartbeat_seconds = $InvalidInterval
    $PrivateConfig | ConvertTo-Json | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
    Assert-Rejected { Resolve-WorkstationConfiguration -ConfigPath $ConfigPath } 'update interval' $SyntheticKey
  }
  $PrivateConfig.heartbeat_seconds = 60
  $PrivateConfig.collect_username = 'yes'
  $PrivateConfig | ConvertTo-Json | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
  Assert-Rejected { Resolve-WorkstationConfiguration -ConfigPath $ConfigPath } 'username setting' $SyntheticKey
  $PrivateConfig.collect_username = $true
  $PrivateConfig.allow_local_http = $true
  $PrivateConfig | ConvertTo-Json | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
  Assert-Rejected { Resolve-WorkstationConfiguration -ConfigPath $ConfigPath } 'requires HTTPS' $SyntheticKey
  ('{"api_token":"' + $SyntheticKey + '", BROKEN JSON') | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
  Assert-Rejected { Resolve-WorkstationConfiguration -ConfigPath $ConfigPath } 'valid JSON file' $SyntheticKey

  # Exercise the installer body and stop at its first task lookup. The temporary
  # copy omits only the administrator requirement, so tests can run unprivileged.
  # No Windows task APIs, file installation or dependency downloads are executed.
  $TestWindowsSource = Join-Path $TestDirectory 'agent/windows'
  [void][IO.Directory]::CreateDirectory($TestWindowsSource)
  Copy-Item (Join-Path $WindowsSource 'configuration.ps1') $TestWindowsSource
  $TestInstaller = Join-Path $TestWindowsSource 'install.ps1'
  $InstallerBody = [IO.File]::ReadAllText((Join-Path $WindowsSource 'install.ps1'))
  $InstallerBody.Replace('#Requires -RunAsAdministrator', '# Administrator requirement omitted for mocked preflight tests only.') | Set-Content -LiteralPath $TestInstaller -Encoding UTF8
  $global:WorkstationTestTaskLookupReached = $false
  function Get-ScheduledTask {
    param($TaskName, $ErrorAction)
    $global:WorkstationTestTaskLookupReached = $true
    throw 'TEST STOP: validated preflight reached task lookup'
  }
  Assert-Rejected { & $TestInstaller -ApiKey $ShortKey } 'valid provisioned' 'invalid-short-key'
  Assert-Condition (-not $global:WorkstationTestTaskLookupReached) 'An invalid key reached task management.'
  Assert-Rejected { & $TestInstaller -ConfigPath $ConfigPath } 'valid JSON file' $SyntheticKey
  Assert-Condition (-not $global:WorkstationTestTaskLookupReached) 'An invalid configuration reached task management.'
  Assert-Rejected { & $TestInstaller -ApiKey $SecureKey } 'TEST STOP:' $SyntheticKey
  Assert-Condition $global:WorkstationTestTaskLookupReached 'The real key-only installer did not complete preflight.'
  Assert-Condition (-not (Test-Path (Join-Path $TestDirectory 'StrathclydeWorkstationMonitor'))) 'Preflight changed the installation directory.'

  foreach ($ScriptFile in Get-ChildItem -LiteralPath $WindowsSource -Filter '*.ps1') {
    $ParseTokens = $null
    $ParseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($ScriptFile.FullName, [ref]$ParseTokens, [ref]$ParseErrors)
    Assert-Condition ($ParseErrors.Count -eq 0) ('PowerShell syntax failed: ' + $ScriptFile.Name)
  }
  Write-Host ('PASS: ' + $global:WorkstationTestAssertions + ' configuration, credential handling and installer preflight assertions.')
} finally {
  $env:COMPUTERNAME = $PreviousComputerName
  $env:ProgramData = $PreviousProgramData
  $SecureKey.Dispose()
  if (Test-Path -LiteralPath $TestDirectory) { Remove-Item -LiteralPath $TestDirectory -Recurse -Force }
}
