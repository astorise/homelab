<#
.SYNOPSIS
  Generate a local self-signed Code Signing certificate (.pfx) for testing and development.

.DESCRIPTION
  Creates a self-signed code signing certificate in the CurrentUser\My store,
  exports it to a password-protected PFX file, and optionally exports the .cer
  and installs it into Trusted Root and Trusted Publishers to trust signatures locally.

.PARAMETER Subject
  Certificate subject, e.g. "CN=HomeLab Dev Code Signing".

.PARAMETER PfxPath
  Output PFX path (default: ./certs/codesign-dev.pfx)

.PARAMETER Password
  Password for the PFX. If omitted, prompts securely.

.PARAMETER Years
  Validity in years (default: 2)

.PARAMETER ExportCer
  Also export a CER file next to the PFX.

.PARAMETER InstallTrusted
  Import the CER into CurrentUser Trusted Root and Trusted Publishers stores (local trust).

.USAGE
  scripts/generate-codesign-cert.ps1 -Subject "CN=HomeLab Dev Code Signing" -ExportCer -InstallTrusted

.NOTES
  This is for development/testing. Production signing requires a publicly trusted certificate.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)][string]$Subject = 'CN=HomeLab Dev Code Signing',
  [Parameter(Mandatory=$false)][string]$PfxPath = (Join-Path (Resolve-Path '.') 'certs/codesign-dev.pfx'),
  [Parameter(Mandatory=$false)][string]$PasswordPlain,
  [Parameter(Mandatory=$false)][int]$Years = 2,
  [switch]$ExportCer,
  [switch]$InstallTrusted
)

$ErrorActionPreference = 'Stop'

function Ensure-Dir($path) {
  $dir = Split-Path -Parent $path
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
}

if ($PSBoundParameters.ContainsKey('PasswordPlain') -and -not [string]::IsNullOrWhiteSpace($PasswordPlain)) {
  $PfxPassword = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
} else {
  $PfxPassword = Read-Host -AsSecureString -Prompt 'Enter PFX password'
}

Write-Host "Creating self-signed code signing certificate: $Subject"
$notAfter = (Get-Date).AddYears($Years)

$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject $Subject `
  -KeyAlgorithm RSA -KeyLength 2048 `
  -HashAlgorithm SHA256 `
  -KeyExportPolicy Exportable `
  -CertStoreLocation 'Cert:\CurrentUser\My' `
  -NotAfter $notAfter `
  -FriendlyName $Subject

if (-not $cert) { throw 'Failed to create self-signed certificate' }

Ensure-Dir $PfxPath
Write-Host "Exporting PFX to: $PfxPath"
Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $PfxPassword | Out-Null

if ($ExportCer -or $InstallTrusted) {
  $cerPath = [IO.Path]::ChangeExtension($PfxPath, '.cer')
  Write-Host "Exporting CER to: $cerPath"
  Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null

  if ($InstallTrusted) {
    Write-Host 'Importing CER into CurrentUser Trusted Root and Trusted Publishers...'
    Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\CurrentUser\TrustedPublisher' | Out-Null
    Write-Host 'Local trust installed for the generated certificate.'
  }
}

Write-Host 'Copy to Clipboard (base64 PFX)'
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($PfxPath))
Set-Clipboard -Value $b64

Write-Host 'Done.'
