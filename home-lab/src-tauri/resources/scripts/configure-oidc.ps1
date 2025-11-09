param(
  [string]$Domain,
  [string]$TemplatePath,
  [string]$DestinationPath,
  [int]$HttpPort = 8000,
  [int]$HttpsPort = 8443
)

if ([string]::IsNullOrWhiteSpace($Domain)) {
  Write-Output 'OIDC issuer left unchanged (domain is empty).'
  exit 0
}

$domain = $Domain.Trim()
if ($domain.Length -eq 0) {
  Write-Output 'OIDC issuer left unchanged (domain is empty after trim).'
  exit 0
}

if ($domain -match '^https?://') {
  $issuer = $domain
} else {
  $issuer = 'https://' + $domain
}

if ($issuer.EndsWith('/')) {
  $issuer = $issuer.TrimEnd('/')
}

if ($issuer -notmatch ':[0-9]+($|/)') {
  $issuer = $issuer + ':' + $HttpsPort
}

$cfgDir = [System.IO.Path]::GetDirectoryName($DestinationPath)
if (-not (Test-Path $cfgDir)) {
  New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
}

if (Test-Path $TemplatePath) {
  $json = Get-Content $TemplatePath -Raw | ConvertFrom-Json
} elseif (Test-Path $DestinationPath) {
  $json = Get-Content $DestinationPath -Raw | ConvertFrom-Json
} else {
  $json = [pscustomobject]@{
    http_port = $HttpPort
    https_port = $HttpsPort
    issuer = 'https://127.0.0.1:' + $HttpsPort
    audiences = @()
    clients = @()
    token_ttl_secs = 3600
    log_level = 'info'
  }
}

$json.issuer = $issuer

if (-not ($json.PSObject.Properties.Name -contains 'https_port')) {
  $json | Add-Member -NotePropertyName https_port -NotePropertyValue $HttpsPort -Force
}
if (-not ($json.PSObject.Properties.Name -contains 'http_port')) {
  $json | Add-Member -NotePropertyName http_port -NotePropertyValue $HttpPort -Force
}
if (-not ($json.PSObject.Properties.Name -contains 'log_level')) {
  $json | Add-Member -NotePropertyName log_level -NotePropertyValue 'info' -Force
}

$jsonString = $json | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($DestinationPath, $jsonString, [System.Text.Encoding]::UTF8)

if ($TemplatePath) {
  [System.IO.File]::WriteAllText($TemplatePath, $jsonString, [System.Text.Encoding]::UTF8)
}

Write-Output ("OIDC issuer set to {0}" -f $json.issuer)
