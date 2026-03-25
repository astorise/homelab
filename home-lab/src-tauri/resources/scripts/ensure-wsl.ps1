[CmdletBinding()]
param(
    [switch]$StatusOnly,
    [switch]$ScheduleRetry
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:WslRetryTaskName = 'HomeLabEnsureWsl'

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

function Resolve-MsiexecExecutablePath {
    Resolve-SystemExecutablePath -ExecutableName 'msiexec.exe'
}

function Resolve-SchtasksExecutablePath {
    Resolve-SystemExecutablePath -ExecutableName 'schtasks.exe'
}

function Resolve-WindowsPowerShellPath {
    $roots = @(
        @($env:SystemRoot, $env:WINDIR) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    foreach ($root in $roots) {
        $candidate = Join-Path $root 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $command = Get-Command 'powershell.exe' -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    return $null
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

function Invoke-Msiexec {
    param([string[]]$Arguments)

    $msiexecPath = Resolve-MsiexecExecutablePath
    if ([string]::IsNullOrWhiteSpace($msiexecPath)) {
        throw 'msiexec.exe introuvable.'
    }

    Invoke-ExternalExecutable -ExecutablePath $msiexecPath -Arguments $Arguments
}

function Invoke-Schtasks {
    param([string[]]$Arguments)

    $schtasksPath = Resolve-SchtasksExecutablePath
    if ([string]::IsNullOrWhiteSpace($schtasksPath)) {
        throw 'schtasks.exe introuvable.'
    }

    Invoke-ExternalExecutable -ExecutablePath $schtasksPath -Arguments $Arguments
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

function Test-WslCallMsiMissingFileMessage {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    $lower = $Message.ToLowerInvariant()
    return $lower.Contains('wsl/callmsi/error_file_not_found') -or (
        $lower.Contains('callmsi') -and $lower.Contains('file_not_found')
    )
}

function Get-WslPackageInstallLocation {
    $packages = @()

    try {
        $packages = @(
            Get-AppxPackage -AllUsers *WindowsSubsystemForLinux* -ErrorAction Stop |
                Sort-Object Version -Descending
        )
    } catch {
        $packages = @()
    }

    foreach ($package in $packages) {
        if ($package.InstallLocation -and (Test-Path -LiteralPath $package.InstallLocation)) {
            return $package.InstallLocation
        }
    }

    $programFiles = ${env:ProgramFiles}
    if (-not [string]::IsNullOrWhiteSpace($programFiles)) {
        $windowsApps = Join-Path $programFiles 'WindowsApps'
        if (Test-Path -LiteralPath $windowsApps) {
            $dirs = @(
                Get-ChildItem -LiteralPath $windowsApps -Directory -Filter 'MicrosoftCorporationII.WindowsSubsystemForLinux_*' -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending
            )

            foreach ($dir in $dirs) {
                if ($dir.FullName -and (Test-Path -LiteralPath $dir.FullName)) {
                    return $dir.FullName
                }
            }
        }
    }

    return $null
}

function Resolve-WslPackageMsiPath {
    $installLocation = Get-WslPackageInstallLocation
    if ([string]::IsNullOrWhiteSpace($installLocation)) {
        return $null
    }

    $candidates = @(
        (Join-Path $installLocation 'wsl.msi'),
        (Join-Path (Join-Path $installLocation 'Assets') 'wsl.msi')
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }

    return $null
}

function Register-WslRetryTask {
    if (-not $ScheduleRetry.IsPresent) {
        return
    }

    $powershellPath = Resolve-WindowsPowerShellPath
    if ([string]::IsNullOrWhiteSpace($powershellPath)) {
        throw 'powershell.exe introuvable pour programmer la reprise WSL.'
    }

    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        $scriptPath = $MyInvocation.MyCommand.Path
    }
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        throw 'Impossible de determiner le chemin du script ensure-wsl.ps1.'
    }

    $taskCommand = '"' + $powershellPath + '" -NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '" -ScheduleRetry'
    Write-Info "Programmation d une reprise WSL via la tache planifiee $($script:WslRetryTaskName)."
    $result = Invoke-Schtasks -Arguments @(
        '/Create',
        '/TN', $script:WslRetryTaskName,
        '/SC', 'ONSTART',
        '/RU', 'SYSTEM',
        '/RL', 'HIGHEST',
        '/TR', $taskCommand,
        '/F'
    )
    $details = Join-CommandOutput -Lines $result.Output

    if ($details) {
        Write-Info ("schtasks.exe /Create a renvoye :" + [Environment]::NewLine + $details)
    }

    if ($result.ExitCode -ne 0) {
        if ($details) {
            throw "Impossible de programmer la reprise WSL (code $($result.ExitCode)) :`n$details"
        }

        throw "Impossible de programmer la reprise WSL (code $($result.ExitCode))."
    }
}

function Unregister-WslRetryTask {
    $result = Invoke-Schtasks -Arguments @('/Delete', '/TN', $script:WslRetryTaskName, '/F')
    if (($result.ExitCode -ne 0) -and ($result.ExitCode -ne 1)) {
        $details = Join-CommandOutput -Lines $result.Output
        if ($details) {
            Write-Info ("Impossible de supprimer la tache planifiee WSL :" + [Environment]::NewLine + $details)
        }
    }
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

function Install-WslPackageMsi {
    $msiPath = Resolve-WslPackageMsiPath
    if ([string]::IsNullOrWhiteSpace($msiPath)) {
        throw 'wsl.msi introuvable dans le package WSL.'
    }

    Write-Info "Tentative d installation directe via $msiPath."
    $result = Invoke-Msiexec -Arguments @('/i', $msiPath, '/passive', '/norestart')
    $details = Join-CommandOutput -Lines $result.Output

    if ($details) {
        Write-Info ("wsl.msi a renvoye :" + [Environment]::NewLine + $details)
    }

    [pscustomobject]@{
        ExitCode        = $result.ExitCode
        Details         = $details
        RestartRequired = ($result.ExitCode -eq 3010) -or ($result.ExitCode -eq 1641)
    }
}

function Invoke-WslInstallFlow {
    param(
        [string[]]$Arguments,
        [string]$Label
    )

    $attempt = Invoke-WslInstallAttempt -Arguments $Arguments -Label $Label
    if ($attempt.ExitCode -eq 0) {
        return [pscustomobject]@{
            Success           = $true
            UnsupportedSwitch = $false
            Deferred          = $false
            RestartRequired   = $false
            Details           = $attempt.Details
        }
    }

    if (Test-NoDistributionSwitchUnsupported -Message $attempt.Details) {
        return [pscustomobject]@{
            Success           = $false
            UnsupportedSwitch = $true
            Deferred          = $false
            RestartRequired   = $false
            Details           = $attempt.Details
        }
    }

    if (Test-WslCallMsiMissingFileMessage -Message $attempt.Details) {
        Write-Info 'wsl.exe signale un echec CallMsi. Tentative de secours via wsl.msi.'
        $msiAttempt = Install-WslPackageMsi

        if ($msiAttempt.ExitCode -eq 0) {
            return [pscustomobject]@{
                Success           = $true
                UnsupportedSwitch = $false
                Deferred          = $false
                RestartRequired   = $msiAttempt.RestartRequired
                Details           = $msiAttempt.Details
            }
        }

        if ($msiAttempt.RestartRequired) {
            return [pscustomobject]@{
                Success           = $false
                UnsupportedSwitch = $false
                Deferred          = $true
                RestartRequired   = $true
                Details           = $msiAttempt.Details
            }
        }

        if ($msiAttempt.ExitCode -in @(1500, 1618)) {
            Write-Info 'Une autre installation MSI est deja en cours. La finalisation WSL sera reprise hors du contexte courant.'
            return [pscustomobject]@{
                Success           = $false
                UnsupportedSwitch = $false
                Deferred          = $true
                RestartRequired   = $false
                Details           = $msiAttempt.Details
            }
        }

        if ($msiAttempt.Details) {
            throw "Installation automatique de WSL via wsl.msi echouee (code $($msiAttempt.ExitCode)) :`n$($msiAttempt.Details)"
        }

        throw "Installation automatique de WSL via wsl.msi echouee (code $($msiAttempt.ExitCode))."
    }

    return [pscustomobject]@{
        Success           = $false
        UnsupportedSwitch = $false
        Deferred          = $false
        RestartRequired   = $false
        Details           = $attempt.Details
        ExitCode          = $attempt.ExitCode
    }
}

function Complete-WslInstallLater {
    param([string]$Reason)

    Register-WslRetryTask
    Write-Info "La finalisation WSL sera retentee automatiquement au prochain demarrage. $Reason"
}

function Install-WslIfMissing {
    $restartRequired = $false

    if ([string]::IsNullOrWhiteSpace((Resolve-WslExecutablePath))) {
        Write-Info 'wsl.exe introuvable. Activation des fonctionnalites Windows requises avant l installation de WSL.'
        $restartRequired = Enable-WslWindowsFeatures

        if ([string]::IsNullOrWhiteSpace((Resolve-WslExecutablePath))) {
            Complete-WslInstallLater -Reason 'wsl.exe reste introuvable apres activation des fonctionnalites Windows.'
            return
        }
    }

    $attempt = Invoke-WslInstallFlow -Arguments @('--install', '--no-distribution') -Label 'wsl.exe --install --no-distribution'
    if ($attempt.Success) {
        if ($attempt.RestartRequired) {
            Complete-WslInstallLater -Reason 'L installation WSL demande encore un redemarrage Windows.'
        }
        return
    }

    if ($attempt.UnsupportedSwitch) {
        Write-Info "L option --no-distribution n est pas supportee. Nouvelle tentative avec 'wsl --install'."
        $legacyAttempt = Invoke-WslInstallFlow -Arguments @('--install') -Label 'wsl.exe --install'
        if ($legacyAttempt.Success) {
            if ($legacyAttempt.RestartRequired) {
                Complete-WslInstallLater -Reason 'L installation WSL demande encore un redemarrage Windows.'
            }
            return
        }

        if ($legacyAttempt.Deferred) {
            Complete-WslInstallLater -Reason 'La finalisation WSL doit etre rejouee hors du contexte courant.'
            return
        }

        if ($legacyAttempt.Details) {
            throw "Installation automatique de WSL echouee :`n$($legacyAttempt.Details)"
        }

        throw 'Installation automatique de WSL echouee.'
    }

    if ($attempt.Deferred) {
        Complete-WslInstallLater -Reason 'La finalisation WSL doit etre rejouee hors du contexte courant.'
        return
    }

    if (-not $restartRequired) {
        Write-Info 'Lancement d une activation DISM en secours avant une derniere tentative.'
        $restartRequired = Enable-WslWindowsFeatures

        if ([string]::IsNullOrWhiteSpace((Resolve-WslExecutablePath))) {
            Complete-WslInstallLater -Reason 'Activation DISM effectuee. Un redemarrage Windows est probablement necessaire avant que WSL soit disponible.'
            return
        }

        $retryAttempt = Invoke-WslInstallFlow -Arguments @('--install', '--no-distribution') -Label 'wsl.exe --install --no-distribution'
        if ($retryAttempt.Success) {
            if ($retryAttempt.RestartRequired) {
                Complete-WslInstallLater -Reason 'L installation WSL demande encore un redemarrage Windows.'
            }
            return
        }

        if ($retryAttempt.UnsupportedSwitch) {
            Write-Info "L option --no-distribution n est pas supportee apres activation DISM. Nouvelle tentative avec 'wsl --install'."
            $legacyRetryAttempt = Invoke-WslInstallFlow -Arguments @('--install') -Label 'wsl.exe --install'
            if ($legacyRetryAttempt.Success) {
                if ($legacyRetryAttempt.RestartRequired) {
                    Complete-WslInstallLater -Reason 'L installation WSL demande encore un redemarrage Windows.'
                }
                return
            }

            if ($legacyRetryAttempt.Deferred) {
                Complete-WslInstallLater -Reason 'La finalisation WSL doit etre rejouee hors du contexte courant.'
                return
            }

            if ($legacyRetryAttempt.Details) {
                throw "Installation automatique de WSL echouee :`n$($legacyRetryAttempt.Details)"
            }

            throw 'Installation automatique de WSL echouee.'
        }

        if ($retryAttempt.Deferred) {
            Complete-WslInstallLater -Reason 'La finalisation WSL doit etre rejouee hors du contexte courant.'
            return
        }

        if ($retryAttempt.Details) {
            throw "Installation automatique de WSL echouee :`n$($retryAttempt.Details)"
        }

        throw 'Installation automatique de WSL echouee.'
    }

    Complete-WslInstallLater -Reason 'L installation WSL a ete demandee, mais un redemarrage Windows peut encore etre necessaire.'
}

try {
    $initialState = Get-WslAvailability
    if ($initialState.Available) {
        Unregister-WslRetryTask
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
        Unregister-WslRetryTask
        Write-Info "WSL disponible apres tentative d'installation. $($finalState.Reason)"
        exit 0
    }

    Write-Info "Installation WSL demandee, mais une reprise automatique ou un redemarrage Windows peut encore etre necessaire. $($finalState.Reason)"
    exit 0
} catch {
    Write-Error "[ensure-wsl] $($_.Exception.Message)"
    exit 1
}
