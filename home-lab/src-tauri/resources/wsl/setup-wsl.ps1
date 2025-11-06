[CmdletBinding()]
param(
    [string]$DistroName = 'home-lab-k3s',
    [string]$InstallDir = (Join-Path ${env:ProgramData} 'home-lab\\wsl'),
    [string]$Rootfs     = (Join-Path $PSScriptRoot 'wsl-rootfs.tar'),
    [switch]$ForceImport,
    [string]$CacheDir   = (Join-Path ${env:ProgramData} 'home-lab\\cache'),
    [int]$ApiPort       = 6550
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($ApiPort -lt 1 -or $ApiPort -gt 65535) {
    throw "ApiPort invalide ($ApiPort). La valeur doit etre comprise entre 1 et 65535."
}

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

function Get-LatestK3sReleaseTag {
    $uri = 'https://api.github.com/repos/k3s-io/k3s/releases/latest'
    $headers = @{ 'User-Agent' = 'home-lab-installer' }
    try {
        $resp = Invoke-RestMethod -Uri $uri -Headers $headers
        if (-not $resp.tag_name) {
            throw 'Reponse GitHub inattendue (tag_name absent).'
        }
        return [string]$resp.tag_name
    } catch {
        throw "Impossible de recuperer la version k3s: $($_.Exception.Message)"
    }
}

function Download-K3sBinary {
    param(
        [string]$Tag,
        [string]$CacheRoot
    )

    if (-not (Test-Path -LiteralPath $CacheRoot)) {
        Write-Info "Creation du cache $CacheRoot"
        New-Item -ItemType Directory -Path $CacheRoot -Force | Out-Null
    }

    $k3sCacheRoot = Join-Path $CacheRoot 'k3s'
    if (-not (Test-Path -LiteralPath $k3sCacheRoot)) {
        New-Item -ItemType Directory -Path $k3sCacheRoot -Force | Out-Null
    }

    $versionDir = Join-Path $k3sCacheRoot $Tag
    $binaryPath = Join-Path $versionDir 'k3s'

    if (Test-Path -LiteralPath $binaryPath) {
        $size = (Get-Item -LiteralPath $binaryPath).Length
        if ($size -gt 0) {
            Write-Info "k3s ($Tag) deja present dans le cache : $binaryPath"
            return $binaryPath
        }
        Write-Info "k3s ($Tag) detecte dans le cache mais fichier vide. Nouveau telechargement."
    } else {
        Write-Info "k3s ($Tag) absent du cache. Telechargement en cours ..."
    }

    if (-not (Test-Path -LiteralPath $versionDir)) {
        New-Item -ItemType Directory -Path $versionDir -Force | Out-Null
    }

    $downloadUri = "https://github.com/k3s-io/k3s/releases/download/$Tag/k3s"
    $tempFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ("k3s-{0}-{1}" -f $Tag, [Guid]::NewGuid().ToString('N')))

    try {
        Invoke-WebRequest -Uri $downloadUri -OutFile $tempFile -UseBasicParsing | Out-Null
    } catch {
        if (Test-Path -LiteralPath $tempFile) {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
        throw "Telechargement de k3s echoue: $($_.Exception.Message)"
    }

    Move-Item -LiteralPath $tempFile -Destination $binaryPath -Force
    Write-Info "k3s ($Tag) stocke dans le cache : $binaryPath"
    return $binaryPath
}

function Convert-ToWslPath {
    param(
        [string]$Distro,
        [string]$WindowsPath
    )

    $full = Convert-Path -LiteralPath $WindowsPath

    $escapedForWsl = $full -replace '\\', '\\\\'
    $linux = & wsl.exe -d $Distro -- wslpath -a $escapedForWsl 2>&1
    if ($LASTEXITCODE -eq 0 -and $linux) {
        return $linux.Trim()
    }

    if ($LASTEXITCODE -ne 0 -and $linux) {
        $errorDetails = ($linux | Where-Object { $_ -and $_.Trim().Length -gt 0 }) -join "`n"
    }

    $normalized = $full
    if ($normalized.StartsWith('\\?\')) {
        $normalized = $normalized.Substring(4)
    }

    if ($normalized -match '^(?<drive>[A-Za-z]):(?<tail>\\.*)$') {
        $drive = $Matches['drive'].ToLowerInvariant()
        $tail = $Matches['tail'] -replace '\\', '/'
        return "/mnt/$drive$tail"
    }

    if ($errorDetails) {
        throw "Conversion en chemin WSL echouee pour $full :`n$errorDetails"
    }

    throw "Conversion en chemin WSL echouee pour $full"
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
    $target = '/usr/local/bin/k3s'

    Write-Info "Mise a disposition de k3s dans la distribution $Distro"
    & wsl.exe -d $Distro -- rm -f $target 2>$null | Out-Null

    $linkOutput = & wsl.exe -d $Distro -- ln -s $linuxPath $target 2>&1
    if ($LASTEXITCODE -eq 0) {
        if ($linkOutput) {
            Write-Info ("ln -s a renvoye :" + [Environment]::NewLine + ($linkOutput -join [Environment]::NewLine))
        }
        Write-Info "Lien symbolique cree vers le cache k3s."
        return
    }

    if ($linkOutput) {
        Write-Info ("Impossible de creer le lien symbolique : " + [Environment]::NewLine + ($linkOutput -join [Environment]::NewLine))
    } else {
        Write-Info "Impossible de creer le lien symbolique : ln -s a renvoye le code $LASTEXITCODE"
    }

    $installOutput = & wsl.exe -d $Distro -- install -m 0755 $linuxPath $target 2>&1
    if ($LASTEXITCODE -ne 0) {
        $details = ($installOutput | Where-Object { $_ -and $_.Trim().Length -gt 0 }) -join "`n"
        if ($details) {
            throw "Installation de k3s echouee (code $LASTEXITCODE) :`n$details"
        }
        throw "Installation de k3s echouee (code $LASTEXITCODE)"
    }

    if ($installOutput) {
        Write-Info ("install a renvoye :" + [Environment]::NewLine + ($installOutput -join [Environment]::NewLine))
    }
    Write-Info "Copie de k3s dans le filesystem WSL (fallback)."
}

function Invoke-K3sBootstrap {
    param(
        [string]$Distro,
        [int]$ApiPort,
        [int]$TimeoutSeconds = 180
    )

    Write-Info "Initialisation de k3s (bootstrap) dans $Distro sur le port $ApiPort"
    $range = "{0}-{0}" -f $ApiPort

    $updateEnvTemplate = @'
set -euo pipefail
cat <<'EOF' >/etc/k3s-env
WSL_ROLE=server
PORT_RANGE=__RANGE__
EOF
'@
    $updateEnvScript = $updateEnvTemplate -replace '__RANGE__', $range
    $updateEnvScript = $updateEnvScript -replace "`r`n", "`n"
    $envStd = & wsl.exe -d $Distro -- sh -c $updateEnvScript 2>&1
    $envExit = $LASTEXITCODE
    if ($envExit -ne 0) {
        $details = ($envStd | Where-Object { $_ -and $_.Trim().Length -gt 0 }) -join "`n"
        if ($details) {
            throw "Mise a jour de /etc/k3s-env echouee (code $envExit) :`n$details"
        }
        throw "Mise a jour de /etc/k3s-env echouee (code $envExit)"
    }
    if ($envStd) {
        Write-Info ("Mise a jour /etc/k3s-env :" + [Environment]::NewLine + ($envStd -join [Environment]::NewLine))
    }

    $rangeEscaped = Escape-ShellSingleQuotes -Value $range
    $configTemplate = @'
set -euo pipefail
mkdir -p /etc/rancher/k3s
cat <<'EOF' >/etc/rancher/k3s/config.yaml
write-kubeconfig-mode: "0644"
node-ip: 127.0.0.1
https-listen-port: __PORT__
EOF
'@
    $configScript = $configTemplate -replace '__PORT__', $ApiPort
    $configScript = $configScript -replace "`r`n", "`n"
    $cfgStd = & wsl.exe -d $Distro -- sh -c $configScript 2>&1
    if ($LASTEXITCODE -ne 0) {
        $details = ($cfgStd | Where-Object { $_ -and $_.Trim().Length -gt 0 }) -join "`n"
        if ($details) {
            throw "Mise a jour de /etc/rancher/k3s/config.yaml echouee :`n$details"
        }
        throw "Mise a jour de /etc/rancher/k3s/config.yaml echouee."
    }
    if ($cfgStd) {
        Write-Info ("Mise a jour config.yaml :" + [Environment]::NewLine + ($cfgStd -join [Environment]::NewLine))
    }

    Write-Info "Utilisation du bootstrap integre (mode degrade)."
    Write-Info "Validation du kubeconfig via bootstrap degrade."
    $bootstrapScriptTemplate = @'
#!/bin/sh
set -eu

PORT={0}
TIMEOUT={1}
CONFIG_DIR=/etc/rancher/k3s
KUBECONFIG_PATH=$CONFIG_DIR/k3s.yaml
ADMIN_KUBECONFIG=/var/lib/rancher/k3s/server/cred/admin.kubeconfig

echo "[k3s-bootstrap] Mode degrade actif, port: $PORT"

mkdir -p "$CONFIG_DIR" /root/.kube

if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    cat <<'EOC' >"$CONFIG_DIR/config.yaml"
write-kubeconfig-mode: "0644"
https-listen-port: {0}
EOC
fi

/usr/local/bin/k3s server --https-listen-port "$PORT" --disable traefik --write-kubeconfig "$KUBECONFIG_PATH" --write-kubeconfig-mode 0644 &
K3S_PID=$!

trap 'kill "$K3S_PID" 2>/dev/null || true' INT TERM EXIT

elapsed=0
while [ "$elapsed" -lt "$TIMEOUT" ]; do
    if [ -s "$KUBECONFIG_PATH" ]; then
        install -m 0600 "$KUBECONFIG_PATH" /root/.kube/config
        kill "$K3S_PID" 2>/dev/null || true
        wait "$K3S_PID" 2>/dev/null || true
        trap - INT TERM EXIT
        exit 0
    fi

    if [ -s "$ADMIN_KUBECONFIG" ]; then
        install -m 0644 "$ADMIN_KUBECONFIG" "$KUBECONFIG_PATH"
        install -m 0600 "$KUBECONFIG_PATH" /root/.kube/config
        kill "$K3S_PID" 2>/dev/null || true
        wait "$K3S_PID" 2>/dev/null || true
        trap - INT TERM EXIT
        exit 0
    fi

    if ! kill -0 "$K3S_PID" 2>/dev/null; then
        wait "$K3S_PID" || true
        exit 1
    fi

    sleep 3
    elapsed=$((elapsed + 3))
done

kill "$K3S_PID" 2>/dev/null || true
wait "$K3S_PID" 2>/dev/null || true
if [ -s "$ADMIN_KUBECONFIG" ]; then
    install -m 0644 "$ADMIN_KUBECONFIG" "$KUBECONFIG_PATH"
    install -m 0600 "$KUBECONFIG_PATH" /root/.kube/config
    exit 0
fi
exit 1
'@
    $bootstrapScript = [string]::Format($bootstrapScriptTemplate, $ApiPort, $TimeoutSeconds)
    $fallbackTemplate = @'
set -euo pipefail
cat <<'EOF' >/tmp/homelab-k3s-bootstrap.sh
{0}
EOF
sh /tmp/homelab-k3s-bootstrap.sh
rc=$?
rm -f /tmp/homelab-k3s-bootstrap.sh
exit $rc
'@
    $cmd = [string]::Format($fallbackTemplate, $bootstrapScript)

    $std = & wsl.exe -d $Distro -- sh -c $cmd 2>&1
    $exitCode = $LASTEXITCODE

    $configCheckCmd = @'
set -e
if [ -s /etc/rancher/k3s/k3s.yaml ]; then
    exit 0
fi
if [ -s /root/.kube/config ]; then
    exit 0
fi
exit 1
'@
    & wsl.exe -d $Distro -- sh -c $configCheckCmd 2>$null
    $configExists = ($LASTEXITCODE -eq 0)

    if ($exitCode -ne 0 -and -not $configExists) {
        $details = ($std | Where-Object { $_ -and $_.Trim().Length -gt 0 }) -join "`n"
        if ($details) {
            throw "Initialisation k3s echouee (code $exitCode) :`n$details"
        }
        throw "Initialisation k3s echouee (code $exitCode)"
    }

    if ($exitCode -ne 0 -and $configExists) {
        Write-Info "Bootstrap k3s a renvoye le code $exitCode mais le kubeconfig est present (continuation)."
    }

    $syncScript = @'
set -e
if [ ! -s /etc/rancher/k3s/k3s.yaml ] && [ -s /root/.kube/config ]; then
    install -m 0644 /root/.kube/config /etc/rancher/k3s/k3s.yaml
fi
'@
    & wsl.exe -d $Distro -- sh -c $syncScript 2>$null
    $syncExit = $LASTEXITCODE
    if ($syncExit -ne 0) {
        Write-Info "Synchronisation du kubeconfig depuis /root/.kube/config (code $syncExit)."
    }

    & wsl.exe -d $Distro -- test -s /etc/rancher/k3s/k3s.yaml 2>$null
    if ($LASTEXITCODE -eq 0) {
        $configExists = $true
    }

    if ($std) {
        Write-Info ("Bootstrap k3s : " + [Environment]::NewLine + ($std -join [Environment]::NewLine))
    }

    Write-Info "Etat bootstrap : exit=$exitCode, kubeconfig=$configExists"

    if (-not $configExists) {
        throw "Initialisation de k3s terminee sans kubeconfig."
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
    Write-Info "  - CacheDir    = $CacheDir"
    Write-Info "  - ApiPort     = $ApiPort"

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

    $tag = Get-LatestK3sReleaseTag
    $binary = Download-K3sBinary -Tag $tag -CacheRoot $CacheDir

    $shouldBootstrap = $needsImport
    if ($shouldBootstrap) {
        Write-Info "Instance nouvellement importee : bootstrap k3s requis."
    } else {
        Write-Info "Verification de la presence du kubeconfig k3s dans $DistroName"
        & wsl.exe -d $DistroName -- test -s /etc/rancher/k3s/k3s.yaml 2>$null
        if ($LASTEXITCODE -ne 0) {
            $shouldBootstrap = $true
            Write-Info "kubeconfig k3s manquant : bootstrap sera lance."
        } else {
            Write-Info "kubeconfig k3s deja present : bootstrap ignore."
        }
    }

    Install-K3sBinary -Distro $DistroName -WindowsBinaryPath $binary
    if ($shouldBootstrap) {
        Invoke-K3sBootstrap -Distro $DistroName -ApiPort $ApiPort
    } else {
        Write-Info "Bootstrap k3s ignore (kubeconfig deja present)."
    }

    Write-Info "Configuration WSL terminee."
    exit 0
} catch {
    Write-Error "[wsl-setup] $($_.Exception.Message)"
    exit 1
}
