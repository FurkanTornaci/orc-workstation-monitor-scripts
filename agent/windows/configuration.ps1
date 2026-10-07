#Requires -Version 5.1

function Resolve-WorkstationConfiguration {
  [CmdletBinding(DefaultParameterSetName = 'ApiKey')]
  param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ConfigFile')]
    [string]$ConfigPath,
    [Parameter(ParameterSetName = 'ApiKey')]
    [Security.SecureString]$ApiKey,
    [Parameter(ParameterSetName = 'ApiKey')]
    [string]$ApiUrl = 'https://strathclyde-workstation-monitor.furkantornaci.workers.dev',
    [Parameter(ParameterSetName = 'ApiKey')]
    [string]$Hostname = $env:COMPUTERNAME,
    [switch]$HideUsername
  )

  if ($PSCmdlet.ParameterSetName -eq 'ConfigFile') {
    try {
      $ConfigFile = Get-Item -LiteralPath $ConfigPath -ErrorAction Stop
      if ($ConfigFile.PSIsContainer -or $ConfigFile.Length -gt 65536) { throw 'Invalid configuration file' }
      $Configuration = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
      # JSON parse errors can include fragments of the private configuration.
      throw 'Cannot read the private configuration. Supply a valid JSON file smaller than 64 KB.'
    }
    if ($null -eq $Configuration -or $Configuration -isnot [pscustomobject]) {
      throw 'The private configuration must be a JSON object.'
    }
  } else {
    if (-not $PSBoundParameters.ContainsKey('ApiKey')) {
      $ApiKey = Read-Host 'Workstation API key (input hidden)' -AsSecureString
    }
    if ($null -eq $ApiKey -or $ApiKey.Length -eq 0) { throw 'A provisioned workstation API key is required.' }
    $Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey)
    try {
      $Token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pointer)
      $Configuration = [pscustomobject]@{
        api_url = $ApiUrl
        hostname = $Hostname
        api_token = $Token
        heartbeat_seconds = 60
        collect_username = $true
        allow_local_http = $false
      }
    } finally {
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer)
      $Token = $null
      $ApiKey = $null
    }
  }

  $Origin = $null
  if (
    $Configuration.api_url -isnot [string] -or
    -not [Uri]::TryCreate($Configuration.api_url, [UriKind]::Absolute, [ref]$Origin) -or
    $Origin.Scheme -ne 'https' -or -not $Origin.Host -or
    $Origin.UserInfo -or $Origin.Query -or $Origin.Fragment -or
    $Origin.AbsolutePath -ne '/'
  ) {
    throw 'The monitor address must be an HTTPS server origin without credentials, a path, a query or a fragment.'
  }
  if (
    $Configuration.api_token -isnot [string] -or
    $Configuration.api_token -cnotmatch '\A[A-Za-z0-9_-]{43,128}\z' -or
    $Configuration.api_token.StartsWith('REPLACE')
  ) {
    throw 'A valid provisioned workstation API key is required.'
  }
  $DeviceName = $Configuration.hostname
  if (-not $DeviceName) { $DeviceName = $env:COMPUTERNAME }
  if ($DeviceName -isnot [string] -or $DeviceName -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9-]{0,62}\z') {
    throw 'A valid Windows device name or workstation label is required.'
  }
  $Interval = 60
  if ($Configuration.PSObject.Properties['heartbeat_seconds']) { $Interval = $Configuration.heartbeat_seconds }
  if (
    ($Interval -isnot [int] -and $Interval -isnot [long] -and $Interval -isnot [double] -and $Interval -isnot [decimal]) -or
    [double]::IsNaN([double]$Interval) -or [double]::IsInfinity([double]$Interval) -or
    $Interval -lt 30 -or $Interval -gt 120
  ) {
    throw 'The update interval must be a number between 30 and 120 seconds.'
  }
  $CollectUsername = $true
  if ($Configuration.PSObject.Properties['collect_username']) {
    if ($Configuration.collect_username -isnot [bool]) { throw 'The username setting must be true or false.' }
    $CollectUsername = $Configuration.collect_username
  }
  if (
    $Configuration.PSObject.Properties['allow_local_http'] -and
    ($Configuration.allow_local_http -isnot [bool] -or $Configuration.allow_local_http)
  ) {
    throw 'The Windows installer requires HTTPS; local HTTP is not supported for installation.'
  }

  # Return only validated fields. The caller stores this in the protected directory.
  return [pscustomobject]@{
    api_url = $Origin.AbsoluteUri.TrimEnd('/')
    hostname = $DeviceName.ToUpperInvariant()
    api_token = $Configuration.api_token
    heartbeat_seconds = $Interval
    collect_username = ($CollectUsername -and -not $HideUsername)
    allow_local_http = $false
  }
}
