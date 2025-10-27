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
        throw "Impossible de récupérer la liste des distributions WSL (code $LASTEXITCODE)."
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
        Write-Info "Création du dossier cible $TargetDir"
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

function Get-LatestK3sReleaseTag {
    $uri = 'https://api.github.com/repos/k3s-io/k3s/releases/latest'
    $headers = @{ 'User-Agent' = 'home-lab-installer' }
    try {
        $resp = Invoke-RestMethod -Uri $uri -Headers $headers
        if (-not $resp.tag_name) {
            throw 'Réponse GitHub inattendue (tag_name absent).'
        }
        return [string]$resp.tag_name
    } catch {
        throw "Impossible de récupérer la version k3s: $($_.Exception.Message)"
    }
}

function Download-K3sBinary {
    param(
        [string]$Tag
    )

    $downloadUri = "https://github.com/k3s-io/k3s/releases/download/$Tag/k3s"
    $tempFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "k3s-$Tag")

    Write-Info "Téléchargement de k3s ($Tag) ..."
    try {
        Invoke-WebRequest -Uri $downloadUri -OutFile $tempFile -UseBasicParsing | Out-Null
    } catch {
        throw "Téléchargement de k3s échoué: $($_.Exception.Message)"
    }

    return $tempFile
}

function Convert-ToWslPath {
    param(
        [string]$Distro,
        [string]$WindowsPath
    )

    $full = Convert-Path -LiteralPath $WindowsPath
    $linux = (& wsl.exe -d $Distro -- wslpath -a "$full" 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $linux) {
        throw "Conversion en chemin WSL échouée pour $full"
    }
    return $linux.Trim()
}

function Escape-ShellSingleQuotes {
    param([string]$Value)
    return $Value -replace "'", "'""'""'"
}

function Install-K3sBinary {
    param(
        [string]$Distro,
        [string]$WindowsBinaryPath
    )

    $linuxPath = Convert-ToWslPath -Distro $Distro -WindowsPath $WindowsBinaryPath
    $escaped = Escape-ShellSingleQuotes -Value $linuxPath
    $cmd = "set -euo pipefail; install -m 0755 '$escaped' /usr/local/bin/k3s"
    Write-Info "Installation de k3s dans la distribution $Distro"
    $p = Start-Process -FilePath 'wsl.exe' -ArgumentList @('-d', $Distro, '--', 'sh', '-c', $cmd) -Wait -PassThru -NoNewWindow
    if ($p.ExitCode -ne 0) {
        throw "Installation de k3s échouée (code $($p.ExitCode))"
    }
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Ensure-WslBinary

    $distros = @(Get-RegisteredDistros)
    $needsImport = $ForceImport.IsPresent -or -not ($distros -contains $DistroName)

    if ($needsImport) {
        Import-Distro -Name $DistroName -TargetDir $InstallDir -TarPath $Rootfs
    } else {
        Write-Info "Distribution $DistroName déjà présente, import ignoré."
    }

    $tag = Get-LatestK3sReleaseTag
    $binary = Download-K3sBinary -Tag $tag

    try {
        Install-K3sBinary -Distro $DistroName -WindowsBinaryPath $binary
    } finally {
        if (Test-Path -LiteralPath $binary) {
            Remove-Item -LiteralPath $binary -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Info "Configuration WSL terminée."
    exit 0
} catch {
    Write-Error "[wsl-setup] $($_.Exception.Message)"
    exit 1
}
