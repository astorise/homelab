param(
  [switch]$Wait,
  [switch]$ForceNew,
  [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

function Get-HomeLabInstallCandidates {
  $candidates = New-Object System.Collections.Generic.List[string]
  $uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )

  foreach ($key in $uninstallKeys) {
    Get-ItemProperty $key -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -eq 'home-lab' -and $_.InstallLocation } |
      ForEach-Object {
        $candidates.Add((Join-Path $_.InstallLocation 'homelab-tauri.exe'))
      }
  }

  $knownPaths = @(
    "$env:ProgramFiles\\home-lab\\homelab-tauri.exe",
    "$env:LOCALAPPDATA\\Programs\\home-lab\\homelab-tauri.exe"
  )

  foreach ($path in $knownPaths) {
    $candidates.Add($path)
  }

  $seen = @{}
  foreach ($candidate in $candidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) {
      continue
    }
    if (-not $seen.ContainsKey($candidate)) {
      $seen[$candidate] = $true
      $candidate
    }
  }
}

function Resolve-HomeLabExe {
  param([string[]]$Candidates)

  foreach ($candidate in $Candidates) {
    if (Test-Path $candidate) {
      return (Resolve-Path $candidate).Path
    }
  }

  return $null
}

$candidates = @(Get-HomeLabInstallCandidates)
$exe = Resolve-HomeLabExe -Candidates $candidates

if (-not $exe) {
  $checked = if ($candidates.Count -gt 0) { $candidates -join '; ' } else { '(aucun chemin trouvé)' }
  throw "Impossible de trouver homelab-tauri.exe. Chemins verifiés: $checked"
}

$running = Get-Process -Name 'homelab-tauri' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($running -and -not $ForceNew) {
  Write-Host "home-lab est deja lance (PID=$($running.Id)). Utilise -ForceNew pour ouvrir une nouvelle instance."
  if ($PassThru) {
    $running
  }
  exit 0
}

$proc = Start-Process -FilePath $exe -PassThru
Write-Host "home-lab lance: $exe (PID=$($proc.Id))"

if ($Wait) {
  $proc.WaitForExit()
  Write-Host "home-lab termine (ExitCode=$($proc.ExitCode))."
}

if ($PassThru) {
  $proc
}
