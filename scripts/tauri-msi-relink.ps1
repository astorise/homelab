<#
.SYNOPSIS
  Build Tauri MSI, then re-link with WiX Light to include our service fragment
  so the MSI installs/uninstalls Windows services and emits traces.

.USAGE
  # From repo root (PowerShell as admin recommended)
  scripts/tauri-msi-relink.ps1 -Build -Relink -Install -Verify

  # Just rebuild + relink
  scripts/tauri-msi-relink.ps1 -Build -Relink

  # Only relink an already built MSI
  scripts/tauri-msi-relink.ps1 -Relink

.NOTES
  Requires Tauri’s WiX toolset at $env:LOCALAPPDATA\tauri\WixTools314
#>
param(
  [switch]$Build,
  [switch]$Relink,
  [switch]$Install,
  [switch]$Verify
)

$ErrorActionPreference = 'Stop'

Write-Warning 'tauri-msi-relink.ps1 is deprecated. Tauri MSI already embeds service actions via resources/install-services.wxs.'
Write-Host    'Use -Relink only if you know you need it. Default flow skips relinking.'

function Get-WixTools {
  $base = Join-Path $env:LOCALAPPDATA 'tauri\WixTools314'
  $candle = Join-Path $base 'candle.exe'
  $light  = Join-Path $base 'light.exe'
  if (-not (Test-Path $candle) -or -not (Test-Path $light)) {
    throw "WiX tools not found under $base (build a Tauri MSI once to download them)"
  }
  return [pscustomobject]@{ Base=$base; Candle=$candle; Light=$light }
}

function Build-TauriMsi {
  Write-Host '=== Building MSI via Tauri (npm run tauri build -b msi) ==='
  $root = Resolve-Path (Join-Path $PSScriptRoot '..')
  $appDir = Join-Path $root 'home-lab'
  Push-Location $appDir
  try {
    & cmd.exe /c "npm run tauri build -- -b msi" | Write-Host
  } finally { Pop-Location }
}

function Relink-Msi {
  $wix = Get-WixTools
  $wixDir = Join-Path $PSScriptRoot '..\target\release\wix\x64' | Resolve-Path
  $frag  = Join-Path $PSScriptRoot '..\home-lab\src-tauri\resources\install-services.wxs' | Resolve-Path
  if (-not (Test-Path $wixDir)) { throw "WiX output dir not found: $wixDir" }
  if (-not (Test-Path $frag))   { throw "Fragment not found: $frag" }

  Push-Location $wixDir
  try {
    Write-Host '=== Compiling fragment (candle) ==='
    & $($wix.Candle) -nologo -v -ext WixUIExtension -out install-services.wixobj $frag | Write-Host

    $outMsi = Resolve-Path '..\..\bundle\msi\home-lab_0.1.0_x64_en-US.msi'
    $outRelinked = (Join-Path (Split-Path $outMsi -Parent) 'home-lab_0.1.0_x64_en-US_services.msi')

    Write-Host '=== Linking (light) main.wixobj + install-services.wixobj ==='
    & $($wix.Light) -nologo -v -ext WixUIExtension -loc locale.wxl -out $outRelinked main.wixobj install-services.wixobj | Write-Host

    Write-Host "Relinked MSI => $outRelinked"
    return $outRelinked
  } finally { Pop-Location }
}

function Install-MsiWithLog($msiPath) {
  if (-not (Test-Path $msiPath)) { throw "MSI not found: $msiPath" }
  $log = Join-Path $env:TEMP 'home-lab-install.log'
  Write-Host "=== Installing MSI: $msiPath (log: $log) ==="
  $p = Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /passive /norestart /l*v `"$log`"" -Wait -PassThru
  Write-Host "msiexec exit code: $($p.ExitCode)"
  if (Test-Path $log) { Get-Content $log -Tail 100 | Write-Host }
  $svcLog = 'C:\Program Files\home-lab\installer-msi.log'
  if (Test-Path $svcLog) { Write-Host '--- installer-msi.log (tail) ---'; Get-Content $svcLog -Tail 80 | Write-Host }
}

function Verify-Services {
  Write-Host '=== Service status ==='
  $svcs = Get-Service -Name HomeDnsService, HomeHttpService -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType
  if ($svcs) { $svcs | Format-Table -AutoSize | Out-String | Write-Host } else { Write-Host '(no services found)' }
  return ($svcs -and ($svcs | Where-Object { $_.Name -eq 'HomeDnsService' -or $_.Name -eq 'HomeHttpService' } | Measure-Object).Count -eq 2)
}

function Ensure-ServicesIfMissing {
  param([string]$InstallDir = 'C:\\Program Files\\home-lab')
  $bin = Join-Path $InstallDir 'bin'
  $dnsExe = Join-Path $bin 'home-dns.exe'
  $httpExe = Join-Path $bin 'home-http.exe'

  $needDns = -not (Get-Service -Name HomeDnsService -ErrorAction SilentlyContinue)
  $needHttp = -not (Get-Service -Name HomeHttpService -ErrorAction SilentlyContinue)

  if (-not $needDns -and -not $needHttp) { Write-Host 'Services already present.'; return }

  Write-Host '=== Fallback: installing missing services via bundled executables ==='
  if ($needDns -and (Test-Path $dnsExe)) {
    Write-Host "Installing DNS service: $dnsExe install"
    & $dnsExe install | Write-Host
  }
  if ($needHttp -and (Test-Path $httpExe)) {
    Write-Host "Installing HTTP service: $httpExe install"
    & $httpExe install | Write-Host
  }

  # Try starting them (best effort)
  try { sc.exe start HomeDnsService  | Out-Null } catch {}
  try { sc.exe start HomeHttpService | Out-Null } catch {}

  $ok = Verify-Services
  if (-not $ok) {
    Write-Host '=== Creating missing services via sc.exe create (fallback) ==='
    if (-not (Get-Service -Name HomeDnsService -ErrorAction SilentlyContinue)) {
      $dnsPath = Join-Path $bin 'home-dns.exe'
      $binArg = '"' + $dnsPath + '" run'
      Write-Host "New-Service -Name HomeDnsService -BinaryPathName $binArg -DisplayName 'Home DNS Service' -StartupType Automatic"
      try { New-Service -Name HomeDnsService -BinaryPathName $binArg -DisplayName 'Home DNS Service' -StartupType Automatic | Out-Null } catch { Write-Warning $_ }
      try { sc.exe start HomeDnsService | Out-Null } catch { Write-Warning $_ }
    }
    if (-not (Get-Service -Name HomeHttpService -ErrorAction SilentlyContinue)) {
      $httpPath = Join-Path $bin 'home-http.exe'
      $binArg2 = '"' + $httpPath + '" run'
      Write-Host "New-Service -Name HomeHttpService -BinaryPathName $binArg2 -DisplayName 'Home HTTP Service' -StartupType Automatic"
      try { New-Service -Name HomeHttpService -BinaryPathName $binArg2 -DisplayName 'Home HTTP Service' -StartupType Automatic | Out-Null } catch { Write-Warning $_ }
      try { sc.exe start HomeHttpService | Out-Null } catch { Write-Warning $_ }
    }
    Verify-Services | Out-Null
  }
}

# Default behavior: build, install, verify — but DO NOT relink
if (-not ($Build -or $Relink -or $Install -or $Verify)) { $Build=$true; $Install=$true; $Verify=$true }

$msiOut = $null
if ($Build) { Build-TauriMsi }
if ($Relink) { $msiOut = Relink-Msi }

# Prefer the standard Tauri MSI artifact if we didn't relink or relink produced no path
if (-not $msiOut) { $msiOut = Resolve-Path 'home-lab\\target\\release\\bundle\\msi\\home-lab_0.1.0_x64_en-US.msi' -ErrorAction SilentlyContinue }
if (-not $msiOut) { $msiOut = Resolve-Path 'target\\release\\bundle\\msi\\home-lab_0.1.0_x64_en-US.msi' -ErrorAction SilentlyContinue }
if ($Install) {
  if (-not $msiOut) { $msiOut = Resolve-Path 'target\release\bundle\msi\home-lab_0.1.0_x64_en-US_services.msi' -ErrorAction SilentlyContinue }
  Install-MsiWithLog $msiOut
}
if ($Verify) {
  $ok = Verify-Services
  if (-not $ok) { Ensure-ServicesIfMissing }
}

Write-Host 'Done.'
