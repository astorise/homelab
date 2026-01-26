[CmdletBinding()]
param(
    [string]$DistroName = 'home-lab-k3s',
    [string]$InstallDir = (Join-Path ${env:ProgramData} 'home-lab\\wsl'),
    [string]$Rootfs     = (Join-Path $PSScriptRoot 'wsl-rootfs.tar'),
    [switch]$ForceImport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info {
    param([string]$Message)
    Write-Host "[wsl-setup] $Message"
}

function Ensure-WslBinary {
    if (-not (Get-Command 'wsl.exe' -ErrorAction SilentlyContinue)) {
        throw 'wsl.exe introuvable. Activez WSL (wsl --install) puis relancez.'
    }
}

function Get-RegisteredDistros {
    $list = & wsl.exe -l -q 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Impossible de recuperer la liste des distributions WSL (code $LASTEXITCODE)."
    }
    $list | Where-Object { $_ -and ($_.Trim().Length -gt 0) } | ForEach-Object { $_.Trim() }
}

function Import-Distro {
    param(
        [string]$Name,
        [string]$TargetDir,
        [string]$TarPath
    )

    if (-not (Test-Path -LiteralPath $TarPath)) {
        throw "Archive rootfs introuvable: $TarPath"
    }

    if (-not (Test-Path -LiteralPath $TargetDir)) {
        Write-Info "Creation du dossier cible $TargetDir"
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }

    Write-Info "Import de la distribution $Name depuis $TarPath"
    $args = @("--import", $Name, $TargetDir, $TarPath, "--version", "2")
    $std = & wsl.exe @args 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        $details = ($std | Where-Object { $_ -and $_.Trim().Length -gt 0 }) -join "`n"
        if ($details) {
            throw "Import WSL echoue (code $exitCode) :`n$details"
        }
        throw "Import WSL echoue (code $exitCode)"
    }

    if ($std) {
        Write-Info ("wsl.exe a renvoye:" + [Environment]::NewLine + ($std -join [Environment]::NewLine))
    }
}

function Remove-Distro {
    param(
        [string]$Name,
        [string]$TargetDir
    )

    Write-Info "Suppression de la distribution $Name existante"
    $std = & wsl.exe --unregister $Name 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        $details = ($std | Where-Object { $_ -and $_.Trim().Length -gt 0 }) -join "`n"
        if ($details) {
            throw "Suppression WSL echoue (code $exitCode) :`n$details"
        }
        throw "Suppression WSL echoue (code $exitCode)"
    }

    if ($std) {
        Write-Info ("wsl.exe a renvoye:" + [Environment]::NewLine + ($std -join [Environment]::NewLine))
    }

    $maxAttempts = 10
    if (Test-Path -LiteralPath $TargetDir) {
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            try {
                Remove-Item -LiteralPath $TargetDir -Recurse -Force -ErrorAction Stop
                break
            } catch {
                if ($attempt -eq $maxAttempts) {
                    throw "Impossible de supprimer le dossier existant $TargetDir : $($_.Exception.Message)"
                }
                Start-Sleep -Milliseconds 500
            }
        }
        if (Test-Path -LiteralPath $TargetDir) {
            throw "Le dossier existant $TargetDir n'a pas pu etre supprime malgre $maxAttempts tentatives."
        }
        Write-Info "Dossier $TargetDir supprime."
    }
}

function Clear-K3sLocks {
    param(
        [string]$Distro
    )

    $cmd = @'
set -euo pipefail
LOCK_FILE="/var/lib/rancher/k3s/data/.lock"
if [ -f "$LOCK_FILE" ]; then
    rm -f "$LOCK_FILE"
fi
if pidof k3s >/dev/null 2>&1; then
    pkill k3s || true
fi
'@
    Write-Info "Nettoyage des verrous k3s (si presents)"
    & wsl.exe -d $Distro -- sh -c $cmd 2>$null | Out-Null
}

function Invoke-K3sBootstrap {
    param(
        [string]$Distro,
        [int]$TimeoutSeconds = 180
    )

    Write-Info "Initialisation de k3s (bootstrap) dans $Distro"
    $cmd = "set -euo pipefail; BOOTSTRAP_ONLY=1 BOOTSTRAP_TIMEOUT=$TimeoutSeconds /usr/local/bin/k3s-init.sh"
    $std = & wsl.exe -d $Distro -- sh -c $cmd 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        $details = ($std | Where-Object { $_ -and $_.Trim().Length -gt 0 }) -join "`n"
        if ($details) {
            throw "Initialisation k3s echouee (code $exitCode) :`n$details"
        }
        throw "Initialisation k3s echouee (code $exitCode)"
    }

    if ($std) {
        Write-Info ("k3s-init.sh a renvoye :" + [Environment]::NewLine + ($std -join [Environment]::NewLine))
    }
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Ensure-WslBinary

    Write-Info "Parametres d'execution :"
    Write-Info "  - DistroName = $DistroName"
    Write-Info "  - ForceImport = $($ForceImport.IsPresent)"
    Write-Info "  - InstallDir  = $InstallDir"
    Write-Info "  - Rootfs      = $Rootfs"

    $distros = @(Get-RegisteredDistros)
    $detected = if ($distros.Count -gt 0) { $distros -join ', ' } else { '(aucune)' }
    Write-Info "Distributions detectees : $detected"

    $alreadyPresent = $distros -contains $DistroName

    if ($ForceImport.IsPresent -and $alreadyPresent) {
        Write-Info "Reimport force demande : suppression de $DistroName"
        Remove-Distro -Name $DistroName -TargetDir $InstallDir
        $distros = @(Get-RegisteredDistros)
        $alreadyPresent = $distros -contains $DistroName
    } elseif ($ForceImport.IsPresent) {
        Write-Info "Reimport force demande mais $DistroName est absent."
    }

    $needsImport = $ForceImport.IsPresent -or -not $alreadyPresent

    if ($needsImport) {
        Import-Distro -Name $DistroName -TargetDir $InstallDir -TarPath $Rootfs
    } else {
        Write-Info "Distribution $DistroName deja presente, import ignore."
    }

    Clear-K3sLocks -Distro $DistroName
    Invoke-K3sBootstrap -Distro $DistroName

    Write-Info "Configuration WSL terminee."
    exit 0
} catch {
    Write-Error "[wsl-setup] $($_.Exception.Message)"
    exit 1
}
