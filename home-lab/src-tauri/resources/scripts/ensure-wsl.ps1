[CmdletBinding()]
param(
    [switch]$StatusOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info {
    param([string]$Message)
    Write-Host "[ensure-wsl] $Message"
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

function Resolve-SystemExecutablePath {
    param([string]$ExecutableName)

    $roots = @(
        @($env:SystemRoot, $env:WINDIR) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )
    $candidates = @()

    foreach ($root in $roots) {
        $candidate = Join-Path $root ("System32\" + $ExecutableName)
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            $candidates += $candidate
        }
    }

    if ($candidates.Count -gt 0) {
        return $candidates[0]
    }

    $command = Get-Command $ExecutableName -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    return $null
}

function Resolve-WslExecutablePath {
    Resolve-SystemExecutablePath -ExecutableName 'wsl.exe'
}

function Resolve-DismExecutablePath {
    Resolve-SystemExecutablePath -ExecutableName 'dism.exe'
}

function Invoke-ExternalExecutable {
    param(
        [string]$ExecutablePath,
        [string[]]$Arguments
    )

    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
        throw 'Executable introuvable.'
    }

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $ExecutablePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        Output   = @($output)
    }
}

function Invoke-WslExe {
    param([string[]]$Arguments)

    $wslPath = Resolve-WslExecutablePath
    if ([string]::IsNullOrWhiteSpace($wslPath)) {
        throw 'wsl.exe introuvable.'
    }

    Invoke-ExternalExecutable -ExecutablePath $wslPath -Arguments $Arguments
}

function Invoke-DismExe {
    param([string[]]$Arguments)

    $dismPath = Resolve-DismExecutablePath
    if ([string]::IsNullOrWhiteSpace($dismPath)) {
        throw 'dism.exe introuvable.'
    }

    Invoke-ExternalExecutable -ExecutablePath $dismPath -Arguments $Arguments
}

function Test-NoDistroMessage {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    $lower = $Message.ToLowerInvariant()
    return $lower.Contains('no installed distributions') -or $lower.Contains('aucune distribution install')
}

function Test-NoDistributionSwitchUnsupported {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    $lower = $Message.ToLowerInvariant()
    return $lower.Contains('no-distribution') -and (
        $lower.Contains('unknown') -or
        $lower.Contains('unrecognized') -or
        $lower.Contains('option') -or
        $lower.Contains('argument') -or
        $lower.Contains('param')
    )
}

function Get-WslAvailability {
    if ([string]::IsNullOrWhiteSpace((Resolve-WslExecutablePath))) {
        return [pscustomobject]@{
            Available = $false
            Reason    = 'wsl.exe introuvable.'
        }
    }

    foreach ($check in @(
        @{ Label = 'wsl.exe --status'; Args = @('--status') },
        @{ Label = 'wsl.exe --list --quiet'; Args = @('--list', '--quiet') }
    )) {
        $result = Invoke-WslExe -Arguments $check.Args
        $details = Join-CommandOutput -Lines $result.Output

        if ($result.ExitCode -eq 0) {
            return [pscustomobject]@{
                Available = $true
                Reason    = "$($check.Label) a reussi."
            }
        }

        if (Test-NoDistroMessage -Message $details) {
            return [pscustomobject]@{
                Available = $true
                Reason    = "$($check.Label) indique qu'aucune distribution n'est encore installee."
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($details)) {
            $reason = "$($check.Label) a echoue : $details"
        } else {
            $reason = "$($check.Label) a echoue (code $($result.ExitCode))."
        }
    }

    return [pscustomobject]@{
        Available = $false
        Reason    = $reason
    }
}

function Enable-WslWindowsFeatures {
    $restartRequired = $false

    foreach ($featureName in @('Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform')) {
        Write-Info "Activation de la fonctionnalite Windows $featureName via DISM."
        $result = Invoke-DismExe -Arguments @(
            '/online',
            '/enable-feature',
            "/featurename:$featureName",
            '/all',
            '/norestart'
        )
        $details = Join-CommandOutput -Lines $result.Output

        if ($details) {
            Write-Info ("dism.exe pour $featureName a renvoye :" + [Environment]::NewLine + $details)
        }

        if (($result.ExitCode -ne 0) -and ($result.ExitCode -ne 3010)) {
            if ($details) {
                throw "Activation DISM de $featureName echouee (code $($result.ExitCode)) :`n$details"
            }

            throw "Activation DISM de $featureName echouee (code $($result.ExitCode))."
        }

        if ($result.ExitCode -eq 3010) {
            $restartRequired = $true
        }
    }

    return $restartRequired
}

function Invoke-WslInstallAttempt {
    param(
        [string[]]$Arguments,
        [string]$Label
    )

    Write-Info "Lancement de '$Label'."
    $result = Invoke-WslExe -Arguments $Arguments
    $details = Join-CommandOutput -Lines $result.Output

    if ($details) {
        Write-Info ($Label + ' a renvoye :' + [Environment]::NewLine + $details)
    }

    [pscustomobject]@{
        ExitCode = $result.ExitCode
        Details  = $details
    }
}

function Install-WslIfMissing {
    $restartRequired = $false

    if ([string]::IsNullOrWhiteSpace((Resolve-WslExecutablePath))) {
        Write-Info 'wsl.exe introuvable. Activation des fonctionnalites Windows requises avant l installation de WSL.'
        $restartRequired = Enable-WslWindowsFeatures

        if ([string]::IsNullOrWhiteSpace((Resolve-WslExecutablePath))) {
            Write-Info 'wsl.exe reste introuvable apres activation des fonctionnalites Windows. Un redemarrage Windows est probablement necessaire.'
            return
        }
    }

    $attempt = Invoke-WslInstallAttempt -Arguments @('--install', '--no-distribution') -Label 'wsl.exe --install --no-distribution'
    if ($attempt.ExitCode -eq 0) {
        return
    }

    if (Test-NoDistributionSwitchUnsupported -Message $attempt.Details) {
        Write-Info "L option --no-distribution n est pas supportee. Nouvelle tentative avec 'wsl --install'."
        $legacyAttempt = Invoke-WslInstallAttempt -Arguments @('--install') -Label 'wsl.exe --install'
        if ($legacyAttempt.ExitCode -eq 0) {
            return
        }

        if ($legacyAttempt.Details) {
            throw "Installation automatique de WSL echouee (code $($legacyAttempt.ExitCode)) :`n$($legacyAttempt.Details)"
        }

        throw "Installation automatique de WSL echouee (code $($legacyAttempt.ExitCode))."
    }

    if (-not $restartRequired) {
        Write-Info 'Lancement d une activation DISM en secours avant une derniere tentative.'
        $restartRequired = Enable-WslWindowsFeatures

        if ([string]::IsNullOrWhiteSpace((Resolve-WslExecutablePath))) {
            Write-Info 'Activation DISM effectuee. Un redemarrage Windows est probablement necessaire avant que WSL soit disponible.'
            return
        }

        $retryAttempt = Invoke-WslInstallAttempt -Arguments @('--install', '--no-distribution') -Label 'wsl.exe --install --no-distribution'
        if ($retryAttempt.ExitCode -eq 0) {
            return
        }

        if (Test-NoDistributionSwitchUnsupported -Message $retryAttempt.Details) {
            Write-Info "L option --no-distribution n est pas supportee apres activation DISM. Nouvelle tentative avec 'wsl --install'."
            $legacyRetryAttempt = Invoke-WslInstallAttempt -Arguments @('--install') -Label 'wsl.exe --install'
            if ($legacyRetryAttempt.ExitCode -eq 0) {
                return
            }

            $attempt = $legacyRetryAttempt
        } else {
            $attempt = $retryAttempt
        }
    }

    if ($restartRequired) {
        Write-Info 'L installation WSL a ete demandee, mais un redemarrage Windows peut encore etre necessaire.'
        return
    }

    if ($attempt.Details) {
        throw "Installation automatique de WSL echouee (code $($attempt.ExitCode)) :`n$($attempt.Details)"
    }

    throw "Installation automatique de WSL echouee (code $($attempt.ExitCode))."
}

try {
    $initialState = Get-WslAvailability
    if ($initialState.Available) {
        Write-Info "WSL deja disponible. $($initialState.Reason)"
        exit 0
    }

    Write-Info $initialState.Reason
    if ($StatusOnly.IsPresent) {
        exit 1
    }

    Install-WslIfMissing

    $finalState = Get-WslAvailability
    if ($finalState.Available) {
        Write-Info "WSL disponible apres tentative d'installation. $($finalState.Reason)"
        exit 0
    }

    Write-Info "Installation WSL demandee, mais un redemarrage Windows peut encore etre necessaire. $($finalState.Reason)"
    exit 0
} catch {
    Write-Error "[ensure-wsl] $($_.Exception.Message)"
    exit 1
}
