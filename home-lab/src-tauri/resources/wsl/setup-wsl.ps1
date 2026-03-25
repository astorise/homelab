[CmdletBinding()]
param(
    [string]$DistroName = 'home-lab-k3s',
    [string]$InstallDir = (Join-Path ${env:ProgramData} 'home-lab\\wsl'),
    [string]$Rootfs     = '',
    [int]$ApiPort       = 0,
    [int]$NodePortSpan  = 57,
    [switch]$ForceImport,
    [switch]$EnableNvidia
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

function Normalize-WindowsPath {
    param([string]$PathValue)

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return $PathValue
    }

    if ($PathValue.StartsWith('\\?\UNC\')) {
        return ('\\' + $PathValue.Substring(8))
    }

    if ($PathValue.StartsWith('\\?\')) {
        return $PathValue.Substring(4)
    }

    return $PathValue
}

function Normalize-CommandOutputLine {
    param($Value)

    if ($null -eq $Value) {
        return ''
    }

    return (([string]$Value) -replace "`0", '').Trim()
}

function Join-CommandOutput {
    param([object[]]$Lines)

    @(
        $Lines |
            ForEach-Object { Normalize-CommandOutputLine -Value $_ } |
            Where-Object { $_ -and $_.Length -gt 0 }
    ) -join "`n"
}

function Invoke-WslExe {
    param([string[]]$Arguments)

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & wsl.exe @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        Output   = @($output)
    }
}

function Get-ScriptDirectory {
    $cached = Get-Variable -Name SetupScriptDir -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not [string]::IsNullOrWhiteSpace($cached)) {
        return $cached
    }

    $candidate = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = [System.IO.Path]::GetDirectoryName($PSCommandPath)
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        throw 'Impossible de determiner le dossier du script setup-wsl.ps1.'
    }

    $candidate = Normalize-WindowsPath -PathValue $candidate

    Set-Variable -Name SetupScriptDir -Scope Script -Value $candidate
    return $candidate
}

function Get-RegisteredDistros {
    $result = Invoke-WslExe -Arguments @('-l', '-q')
    $list = $result.Output
    $exitCode = $result.ExitCode
    if ($exitCode -ne 0) {
        $details = Join-CommandOutput -Lines $list
        if ($details) {
            throw "Impossible de recuperer la liste des distributions WSL (code $exitCode) :`n$details"
        }
        throw "Impossible de recuperer la liste des distributions WSL (code $exitCode)."
    }
    $list `
        | ForEach-Object { Normalize-CommandOutputLine -Value $_ } `
        | Where-Object { $_ -and ($_.Length -gt 0) }
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
    $result = Invoke-WslExe -Arguments $args
    $std = $result.Output
    $exitCode = $result.ExitCode

    if ($exitCode -ne 0) {
        $details = Join-CommandOutput -Lines $std
        if ($details) {
            throw "Import WSL echoue (code $exitCode) :`n$details"
        }
        throw "Import WSL echoue (code $exitCode)"
    }

    if ($std) {
        $details = Join-CommandOutput -Lines $std
        if ($details) {
            Write-Info ("wsl.exe a renvoye:" + [Environment]::NewLine + $details)
        }
    }
}

function Remove-Distro {
    param(
        [string]$Name,
        [string]$TargetDir
    )

    Write-Info "Suppression de la distribution $Name existante"
    $result = Invoke-WslExe -Arguments @('--unregister', $Name)
    $std = $result.Output
    $exitCode = $result.ExitCode

    if ($exitCode -ne 0) {
        $details = Join-CommandOutput -Lines $std
        if ($details) {
            throw "Suppression WSL echoue (code $exitCode) :`n$details"
        }
        throw "Suppression WSL echoue (code $exitCode)"
    }

    if ($std) {
        $details = Join-CommandOutput -Lines $std
        if ($details) {
            Write-Info ("wsl.exe a renvoye:" + [Environment]::NewLine + $details)
        }
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

function Invoke-WslScript {
    param(
        [string]$Distro,
        [string]$Script,
        [string]$Operation
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'wsl.exe'
    $psi.Arguments = "-d $Distro -- sh -s"
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $null = $process.Start()

    $normalizedScript = $Script.Replace("`r`n", "`n").Replace("`r", "`n")
    $process.StandardInput.Write($normalizedScript)
    if (-not $normalizedScript.EndsWith("`n")) {
        $process.StandardInput.Write("`n")
    }
    $process.StandardInput.Close()

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    [pscustomobject]@{
        ExitCode = $process.ExitCode
        Stdout   = $stdout
        Stderr   = $stderr
        Output   = @($stdout, $stderr) | ForEach-Object { Normalize-CommandOutputLine -Value $_ } | Where-Object { $_ -and $_.Length -gt 0 }
    }
}

function Clear-K3sLocks {
    param(
        [string]$Distro
    )

$cmd = @'
set -eu
LOCK_FILE="/var/lib/rancher/k3s/data/.lock"
if [ -f "$LOCK_FILE" ]; then
    rm -f "$LOCK_FILE"
fi
if pidof k3s >/dev/null 2>&1; then
    pkill k3s || true
fi
'@
    Write-Info "Nettoyage des verrous k3s (si presents)"
    $result = Invoke-WslScript -Distro $Distro -Script $cmd -Operation 'Nettoyage des verrous k3s'
    if ($result.ExitCode -ne 0) {
        $result.Output | Out-Null
    }
}

function Test-K3sInitScriptReady {
    param(
        [string]$Distro,
        [string]$Operation = 'Verification k3s-init.sh'
    )

$cmd = @'
set -eu
if [ ! -s /usr/local/bin/k3s-init.sh ]; then
    exit 1
fi
chmod 0755 /usr/local/bin/k3s-init.sh >/dev/null 2>&1 || true
test -r /usr/local/bin/k3s-init.sh
'@
    Invoke-WslScript -Distro $Distro -Script $cmd -Operation $Operation
}

function Wait-K3sInitScriptReady {
    param(
        [string]$Distro,
        [int]$Attempts = 20,
        [int]$DelayMs = 500,
        [string]$Operation = 'Verification k3s-init.sh'
    )

    $lastResult = $null
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $lastResult = Test-K3sInitScriptReady -Distro $Distro -Operation $Operation
        if ($lastResult.ExitCode -eq 0) {
            return [pscustomobject]@{
                Ready  = $true
                Result = $lastResult
            }
        }

        if ($attempt -lt $Attempts) {
            Start-Sleep -Milliseconds $DelayMs
        }
    }

    [pscustomobject]@{
        Ready  = $false
        Result = $lastResult
    }
}

function Test-K3sBinaryReady {
    param(
        [string]$Distro,
        [string]$Operation = 'Verification binaire k3s'
    )

$cmd = @'
set -eu
test -s /usr/local/bin/k3s
test -x /usr/local/bin/k3s
'@
    Invoke-WslScript -Distro $Distro -Script $cmd -Operation $Operation
}

function Get-K3sInitScriptContent {
    $sourcePath = [System.IO.Path]::Combine((Get-ScriptDirectory), 'k3s-init.sh')
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        throw "Script k3s-init.sh introuvable: $sourcePath"
    }

    (Get-Content -Raw -LiteralPath $sourcePath).Replace("`r`n", "`n").Replace("`r", "`n")
}

function New-K3sInitWriteScript {
    param(
        [string]$ScriptContent
    )

    $hereDocMarker = '__HOME_LAB_K3S_INIT_EOF__'
    $markerIndex = 0
    while ($ScriptContent.Contains($hereDocMarker)) {
        $markerIndex += 1
        $hereDocMarker = "__HOME_LAB_K3S_INIT_EOF_$markerIndex__"
    }

    @(
        "cat > /usr/local/bin/k3s-init.sh <<'$hereDocMarker'"
        $ScriptContent.TrimEnd("`n")
        $hereDocMarker
        'chmod 0755 /usr/local/bin/k3s-init.sh'
        'test -s /usr/local/bin/k3s-init.sh'
        'test -r /usr/local/bin/k3s-init.sh'
    ) -join "`n"
}

function Install-K3sInitScript {
    param([string]$Distro)

    Write-Info "Installation du script /usr/local/bin/k3s-init.sh"
    $normalizedScript = Get-K3sInitScriptContent
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $mkdirResult = Invoke-WslScript -Distro $Distro -Script "set -eu; mkdir -p /usr/local/bin" -Operation 'Preparation /usr/local/bin'
    if ($mkdirResult.ExitCode -ne 0) {
        $details = ($mkdirResult.Output) -join "`n"
        if ($details) {
            throw "Preparation /usr/local/bin echouee (code $($mkdirResult.ExitCode)) :`n$details"
        }
        throw "Preparation /usr/local/bin echouee (code $($mkdirResult.ExitCode))"
    }

    $directInstallScript = @(
        'set -eu'
        (New-K3sInitWriteScript -ScriptContent $normalizedScript)
    ) -join "`n"
    $directInstallResult = Invoke-WslScript -Distro $Distro -Script $directInstallScript -Operation 'Installation directe k3s-init.sh'
    if ($directInstallResult.ExitCode -eq 0) {
        return
    }

    $directInstallDetails = ($directInstallResult.Output) -join [Environment]::NewLine
    if ($directInstallDetails) {
        Write-Info ("Installation directe k3s-init.sh non confirmee, fallback via \\wsl$ :" + [Environment]::NewLine + $directInstallDetails)
    } else {
        Write-Info "Installation directe k3s-init.sh non confirmee, fallback via \\wsl$."
    }

    $uncPath = "\\wsl$\$Distro\usr\local\bin\k3s-init.sh"
    $lastWriteError = $null
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        try {
            [System.IO.File]::WriteAllText($uncPath, $normalizedScript, $utf8NoBom)
            $lastWriteError = $null
            break
        } catch {
            $lastWriteError = $_.Exception.Message
            Start-Sleep -Milliseconds 300
        }
    }
    if ($lastWriteError) {
        throw "Installation k3s-init.sh echouee via \\\\wsl$ : $lastWriteError"
    }

    $chmodOk = $false
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        $chmodResult = Invoke-WslScript -Distro $Distro -Script "set -eu; chmod 0755 /usr/local/bin/k3s-init.sh; test -s /usr/local/bin/k3s-init.sh" -Operation 'Activation k3s-init.sh'
        if ($chmodResult.ExitCode -eq 0) {
            $chmodOk = $true
            break
        }
        Start-Sleep -Milliseconds 300
    }

    if (-not [System.IO.File]::Exists($uncPath)) {
        throw "Installation k3s-init.sh echouee : fichier absent apres ecriture via \\\\wsl$."
    }

    $fileInfo = Get-Item -LiteralPath $uncPath
    if ($fileInfo.Length -le 0) {
        throw "Installation k3s-init.sh echouee : fichier vide apres ecriture via \\\\wsl$."
    }

    if (-not $chmodOk) {
        Write-Info "Activation chmod de k3s-init.sh non confirmee immediatement, poursuite avec script present."
    }

    $readyState = Wait-K3sInitScriptReady -Distro $Distro -Attempts 20 -DelayMs 500 -Operation 'Verification k3s-init.sh'
    if (-not $readyState.Ready) {
        Write-Info "Visibilite de k3s-init.sh non confirmee immediatement dans la distribution; verification differee au bootstrap."
    }
}

function Configure-K3sEnv {
    param(
        [string]$Distro,
        [int]$ApiPort,
        [int]$NodePortSpan,
        [int]$StreamPort,
        [psobject]$LocalPorts,
        [switch]$EnableNvidia
    )

    if ($ApiPort -lt 1 -or $ApiPort -gt 65535) {
        throw "ApiPort invalide ($ApiPort). Valeur attendue entre 1 et 65535."
    }
    if ($NodePortSpan -lt 0) {
        throw "NodePortSpan invalide ($NodePortSpan). Valeur attendue >= 0."
    }

    $nodePortRange = Get-K3sNodePortRangeForInstance -Name $Distro -NodePortSpan $NodePortSpan
    $rangeText = "$($nodePortRange.Start)-$($nodePortRange.End)"
    $ingressPorts = Get-IngressPortLayoutForInstance -Name $Distro
    $sshPort = Get-SshPortForInstance -Name $Distro
    Write-Info "Configuration de /etc/k3s-env avec K3S_API_PORT=$ApiPort PORT_RANGE=$rangeText"
    $tlsSans = "$Distro.wsl"
    $content = @"
WSL_ROLE=server
K3S_API_PORT=$ApiPort
PORT_RANGE=$rangeText
CONTAINERD_STREAM_PORT=$StreamPort
K3S_LB_SERVER_PORT=$($LocalPorts.LbServerPort)
K3S_KUBELET_PORT=$($LocalPorts.KubeletPort)
K3S_KUBELET_HEALTHZ_PORT=$($LocalPorts.KubeletHealthzPort)
K3S_KUBE_CONTROLLER_MANAGER_SECURE_PORT=$($LocalPorts.KubeControllerManagerSecurePort)
K3S_KUBE_CLOUD_CONTROLLER_MANAGER_SECURE_PORT=$($LocalPorts.KubeCloudControllerManagerSecurePort)
K3S_KUBE_SCHEDULER_SECURE_PORT=$($LocalPorts.KubeSchedulerSecurePort)
K3S_INGRESS_HTTP_PORT=$($ingressPorts.HttpPort)
K3S_INGRESS_HTTPS_PORT=$($ingressPorts.HttpsPort)
K3S_GIT_SSH_PORT=$sshPort
K3S_TLS_SANS=$tlsSans
"@.Replace("`r`n", "`n").Replace("`r", "`n")

    if ($EnableNvidia.IsPresent) {
        $content += "ENABLE_NVIDIA_TOOLKIT=1`n"
    }

    $uncPath = "\\wsl$\$Distro\etc\k3s-env"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($uncPath, $content, $utf8NoBom)
}

function Configure-K3sAutostart {
    param([string]$Distro)

    Write-Info "Configuration de l'autostart WSL/local.d pour k3s-init.sh"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    $wslConfPath = "\\wsl$\$Distro\etc\wsl.conf"
    $wslConfContent = "[boot]`ncommand=`"sh /usr/local/bin/k3s-init.sh`"`n".Replace("`r`n", "`n").Replace("`r", "`n")
    [System.IO.File]::WriteAllText($wslConfPath, $wslConfContent, $utf8NoBom)

    $localDResult = Invoke-WslScript -Distro $Distro -Script "set -eu; mkdir -p /etc/local.d" -Operation 'Preparation /etc/local.d'
    if ($localDResult.ExitCode -ne 0) {
        $details = ($localDResult.Output) -join "`n"
        if ($details) {
            throw "Preparation /etc/local.d echouee (code $($localDResult.ExitCode)) :`n$details"
        }
        throw "Preparation /etc/local.d echouee (code $($localDResult.ExitCode))"
    }

    $localStartPath = "\\wsl$\$Distro\etc\local.d\k3s.start"
    $localStartContent = "#!/bin/sh`nexec sh /usr/local/bin/k3s-init.sh`n".Replace("`r`n", "`n").Replace("`r", "`n")
    [System.IO.File]::WriteAllText($localStartPath, $localStartContent, $utf8NoBom)

    $chmodResult = Invoke-WslExe -Arguments @('-d', $Distro, '--', 'chmod', '+x', '/etc/local.d/k3s.start')
    if ($chmodResult.ExitCode -ne 0) {
        $chmodStd = $chmodResult.Output
        $details = Join-CommandOutput -Lines $chmodStd
        if ($details) {
            throw "Activation /etc/local.d/k3s.start echouee (code $($chmodResult.ExitCode)) :`n$details"
        }
        throw "Activation /etc/local.d/k3s.start echouee (code $($chmodResult.ExitCode))"
    }
}

function Get-InstanceSlot {
    param([string]$Name)

    if ($Name -eq 'home-lab-k3s') {
        return 0
    }

    $match = [System.Text.RegularExpressions.Regex]::Match($Name, '^home-lab-k3s-(\d+)$')
    if ($match.Success) {
        $index = [int]$match.Groups[1].Value
        if ($index -gt 0) {
            return ($index - 1)
        }
    }

    # Fallback stable slot when the name does not follow home-lab-k3s(-N)
    [uint32]$hash = 2166136261
    foreach ($ch in $Name.ToCharArray()) {
        $hash = [uint32]($hash -bxor [uint32][char]$ch)
        $hash = [uint32](([uint64]$hash * 16777619) % 4294967296)
    }
    return [int]($hash % 1000)
}

function Get-BoundedInstanceSlot {
    param(
        [string]$Name,
        [int]$Capacity
    )

    if ($Capacity -le 1) {
        return 0
    }

    $slot = Get-InstanceSlot -Name $Name
    if ($slot -lt 0) {
        return 0
    }

    return [int]($slot % $Capacity)
}

function Get-DeterministicPortForInstance {
    param(
        [string]$Name,
        [int]$BasePort,
        [int]$Step = 1,
        [int]$MaxPort = 60000
    )

    if ($Step -le 0) {
        $Step = 1
    }
    if ($MaxPort -lt $BasePort) {
        $MaxPort = $BasePort
    }

    $capacity = [int]([Math]::Floor((($MaxPort - $BasePort) / $Step) + 1))
    $slot = Get-BoundedInstanceSlot -Name $Name -Capacity $capacity
    return [int]($BasePort + ($slot * $Step))
}

function Get-K3sNodePortRangeForInstance {
    param(
        [string]$Name,
        [int]$NodePortSpan
    )

    $start = Get-DeterministicPortForInstance -Name $Name -BasePort 20000 -Step 100 -MaxPort 60000
    $end = [Math]::Min(65535, $start + $NodePortSpan)
    [pscustomobject]@{
        Start = [int]$start
        End   = [int]$end
    }
}

function Get-IngressPortLayoutForInstance {
    param([string]$Name)

    # HTTPS is the published backend port; keep one full HTTP/HTTPS pair per instance.
    $httpsPort = Get-DeterministicPortForInstance -Name $Name -BasePort 2001 -Step 2 -MaxPort 60000
    [pscustomobject]@{
        HttpPort  = [int]($httpsPort - 1)
        HttpsPort = [int]$httpsPort
    }
}

function Get-K3sApiPortForInstance {
    param([string]$Name)

    # k3s reserves the adjacent supervisor/apiserver port pair, so instances must
    # advance by 2 to avoid collisions between home-lab-k3s and home-lab-k3s-N.
    return Get-DeterministicPortForInstance -Name $Name -BasePort 1001 -Step 2 -MaxPort 60000
}

function Get-SshPortForInstance {
    param([string]$Name)

    return Get-DeterministicPortForInstance -Name $Name -BasePort 3001 -Step 1 -MaxPort 60000
}

function Get-ContainerdStreamPortForInstance {
    param([string]$Name)

    $basePort = 10010
    $capacity = 65536 - $basePort
    $slot = Get-BoundedInstanceSlot -Name $Name -Capacity $capacity
    $port = $basePort + $slot
    if ($port -gt 65535) {
        throw "Port stream containerd invalide ($port) pour l'instance '$Name'."
    }
    return [int]$port
}

function Get-K3sLocalPortLayoutForInstance {
    param([string]$Name)

    $basePort = 11040
    $step = 20
    $maxOffset = 7
    $capacity = [int]([Math]::Floor(((65535 - $basePort - $maxOffset) / $step) + 1))
    $slot = Get-BoundedInstanceSlot -Name $Name -Capacity $capacity
    $blockBase = $basePort + ($slot * $step)

    [pscustomobject]@{
        LbServerPort                         = [int]$blockBase
        KubeletPort                          = [int]($blockBase + 1)
        KubeletHealthzPort                   = [int]($blockBase + 2)
        KubeControllerManagerSecurePort      = [int]($blockBase + 5)
        KubeCloudControllerManagerSecurePort = [int]($blockBase + 6)
        KubeSchedulerSecurePort              = [int]($blockBase + 7)
    }
}

function Invoke-K3sBootstrap {
    param(
        [string]$Distro,
        [int]$TimeoutSeconds = 180
    )

    Write-Info "Initialisation de k3s (bootstrap) dans $Distro"
    $k3sBinaryState = Test-K3sBinaryReady -Distro $Distro -Operation 'Preparation bootstrap binaire k3s'
    if ($k3sBinaryState.ExitCode -ne 0) {
        $details = if ($k3sBinaryState.Output) {
            ($k3sBinaryState.Output) -join "`n"
        } else {
            ''
        }

        if ($details) {
            Write-Info ("Bootstrap k3s differe : /usr/local/bin/k3s est absent ou non executable." + [Environment]::NewLine + $details)
        } else {
            Write-Info 'Bootstrap k3s differe : /usr/local/bin/k3s est absent ou non executable.'
        }
        return
    }

    $visibilityAttempts = [Math]::Min([Math]::Max([int]($TimeoutSeconds * 2), 20), 120)
    $readyState = Wait-K3sInitScriptReady -Distro $Distro -Attempts $visibilityAttempts -DelayMs 500 -Operation 'Preparation bootstrap k3s-init.sh'
    if (-not $readyState.Ready) {
        $details = if ($readyState.Result -and $readyState.Result.Output) {
            ($readyState.Result.Output) -join "`n"
        } else {
            ''
        }

        if ($details) {
            Write-Info ("Visibilite de k3s-init.sh non confirmee juste avant bootstrap; tentative d'execution directe :" + [Environment]::NewLine + $details)
        } else {
            Write-Info "Visibilite de k3s-init.sh non confirmee juste avant bootstrap; tentative d'execution directe."
        }
    }
    $k3sInitScript = Get-K3sInitScriptContent
    $cmd = @(
        'set -eu'
        (New-K3sInitWriteScript -ScriptContent $k3sInitScript)
        "BOOTSTRAP_ONLY=1 BOOTSTRAP_TIMEOUT=$TimeoutSeconds sh /usr/local/bin/k3s-init.sh"
    ) -join "`n"
    $result = Invoke-WslScript -Distro $Distro -Script $cmd -Operation 'Initialisation k3s'
    $exitCode = $result.ExitCode

    if ($exitCode -ne 0) {
        $details = ($result.Output) -join "`n"
        if ($details) {
            throw "Initialisation k3s echouee (code $exitCode) :`n$details"
        }
        throw "Initialisation k3s echouee (code $exitCode)"
    }

    if ($result.Output) {
        Write-Info ("k3s-init.sh a renvoye :" + [Environment]::NewLine + ($result.Output -join [Environment]::NewLine))
    }
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Ensure-WslBinary
    $InstallDir = Normalize-WindowsPath -PathValue $InstallDir
    $Rootfs = Normalize-WindowsPath -PathValue $Rootfs
    if ([string]::IsNullOrWhiteSpace($Rootfs)) {
        $Rootfs = [System.IO.Path]::Combine((Get-ScriptDirectory), 'wsl-rootfs.tar')
    }
    if ($ApiPort -le 0) {
        $ApiPort = Get-K3sApiPortForInstance -Name $DistroName
    }

    Write-Info "Parametres d'execution :"
    Write-Info "  - DistroName = $DistroName"
    Write-Info "  - ForceImport = $($ForceImport.IsPresent)"
    Write-Info "  - InstallDir  = $InstallDir"
    Write-Info "  - Rootfs      = $Rootfs"
    Write-Info "  - ApiPort     = $ApiPort"
    Write-Info "  - NodePortSpan= $NodePortSpan"
    Write-Info "  - EnableNvidia= $($EnableNvidia.IsPresent)"
    $streamPort = Get-ContainerdStreamPortForInstance -Name $DistroName
    $localPorts = Get-K3sLocalPortLayoutForInstance -Name $DistroName
    Write-Info "  - StreamPort  = $streamPort"
    Write-Info "  - LocalPorts  = lb:$($localPorts.LbServerPort) kubelet:$($localPorts.KubeletPort) kubelet-healthz:$($localPorts.KubeletHealthzPort) controller-manager:$($localPorts.KubeControllerManagerSecurePort) cloud-controller-manager:$($localPorts.KubeCloudControllerManagerSecurePort) scheduler:$($localPorts.KubeSchedulerSecurePort)"

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

    Install-K3sInitScript -Distro $DistroName
    Configure-K3sEnv -Distro $DistroName -ApiPort $ApiPort -NodePortSpan $NodePortSpan -StreamPort $streamPort -LocalPorts $localPorts -EnableNvidia:$EnableNvidia
    Configure-K3sAutostart -Distro $DistroName
    Clear-K3sLocks -Distro $DistroName
    Invoke-K3sBootstrap -Distro $DistroName

    Write-Info "Configuration WSL terminee."
    exit 0
} catch {
    Write-Error "[wsl-setup] $($_.Exception.Message)"
    exit 1
}
