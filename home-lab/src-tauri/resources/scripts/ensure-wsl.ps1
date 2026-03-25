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

function Get-WindowsOptionalFeatureState {
    param([string]$FeatureName)

    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop
        return [string]$feature.State
    } catch {
        return $null
    }
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

    $taskArguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '" -ScheduleRetry'
    Write-Info "Programmation d une reprise WSL via la tache planifiee $($script:WslRetryTaskName)."
    $action = New-ScheduledTaskAction -Execute $powershellPath -Argument $taskArguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $script:WslRetryTaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

function Unregister-WslRetryTask {
    $existingTask = Get-ScheduledTask -TaskName $script:WslRetryTaskName -ErrorAction SilentlyContinue
    if ($null -eq $existingTask) {
        return
    }

    try {
        Unregister-ScheduledTask -TaskName $script:WslRetryTaskName -Confirm:$false -ErrorAction Stop
    } catch {
        Write-Info ("Impossible de supprimer la tache planifiee WSL :" + [Environment]::NewLine + $_.Exception.Message)
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
    $featuresChanged = $false

    foreach ($featureName in @('Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform')) {
        $stateBefore = Get-WindowsOptionalFeatureState -FeatureName $featureName
        if (($stateBefore -ne $null) -and ($stateBefore -ne 'Enabled')) {
            $featuresChanged = $true
        }

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

    if ($featuresChanged) {
        $restartRequired = $true
        Write-Info 'Les fonctionnalites Windows WSL ont ete modifiees. Un redemarrage Windows est requis avant la suite.'
    }

    [pscustomobject]@{
        RestartRequired = $restartRequired
        FeaturesChanged = $featuresChanged
    }
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

function Invoke-WslPackageInstallFlow {
    $msiPath = Resolve-WslPackageMsiPath
    if ([string]::IsNullOrWhiteSpace($msiPath)) {
        return [pscustomobject]@{
            Success         = $false
            PackageFound    = $false
            Deferred        = $false
            RestartRequired = $false
            ContinueWithWsl = $true
            Details         = 'wsl.msi introuvable dans le package WSL.'
        }
    }

    $msiAttempt = Install-WslPackageMsi
    if ($msiAttempt.ExitCode -eq 0) {
        return [pscustomobject]@{
            Success         = $true
            PackageFound    = $true
            Deferred        = $false
            RestartRequired = $msiAttempt.RestartRequired
            ContinueWithWsl = $false
            Details         = $msiAttempt.Details
        }
    }

    if ($msiAttempt.RestartRequired) {
        return [pscustomobject]@{
            Success         = $false
            PackageFound    = $true
            Deferred        = $true
            RestartRequired = $true
            ContinueWithWsl = $false
            Details         = $msiAttempt.Details
        }
    }

    if ($msiAttempt.ExitCode -in @(1500, 1618)) {
        Write-Info 'Une autre installation MSI est deja en cours. La finalisation WSL sera reprise hors du contexte courant.'
        return [pscustomobject]@{
            Success         = $false
            PackageFound    = $true
            Deferred        = $true
            RestartRequired = $false
            ContinueWithWsl = $false
            Details         = $msiAttempt.Details
        }
    }

    if ($msiAttempt.ExitCode -eq 1638) {
        Write-Info 'wsl.msi est deja installe. Bascule sur wsl.exe pour finaliser WSL.'
        return [pscustomobject]@{
            Success         = $false
            PackageFound    = $true
            Deferred        = $false
            RestartRequired = $false
            ContinueWithWsl = $true
            Details         = $msiAttempt.Details
        }
    }

    return [pscustomobject]@{
        Success         = $false
        PackageFound    = $true
        Deferred        = $false
        RestartRequired = $false
        ContinueWithWsl = $false
        Details         = $msiAttempt.Details
        ExitCode        = $msiAttempt.ExitCode
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
    Write-Info 'Activation DISM des fonctionnalites Windows requises avant l installation de WSL.'
    $featureState = Enable-WslWindowsFeatures

    if ($featureState.FeaturesChanged) {
        Complete-WslInstallLater -Reason 'Les fonctionnalites Windows WSL viennent d etre activees et la suite sera reprise apres redemarrage.'
        return
    }

    if ([string]::IsNullOrWhiteSpace((Resolve-WslExecutablePath))) {
        Complete-WslInstallLater -Reason 'wsl.exe reste introuvable apres verification DISM.'
        return
    }

    $msiFlow = Invoke-WslPackageInstallFlow
    if ($msiFlow.Success) {
        if ($msiFlow.RestartRequired -or $featureState.RestartRequired) {
            Complete-WslInstallLater -Reason 'L installation WSL demande encore un redemarrage Windows.'
        }
        return
    }

    if ($msiFlow.Deferred) {
        Complete-WslInstallLater -Reason 'La finalisation WSL doit etre rejouee hors du contexte courant.'
        return
    }

    if (-not $msiFlow.ContinueWithWsl) {
        if ($msiFlow.Details) {
            throw "Installation automatique de WSL via wsl.msi echouee :`n$($msiFlow.Details)"
        }

        throw 'Installation automatique de WSL via wsl.msi echouee.'
    }

    Write-Info 'wsl.msi indisponible ou deja present. Bascule sur wsl.exe.'
    $attempt = Invoke-WslInstallFlow -Arguments @('--install', '--no-distribution') -Label 'wsl.exe --install --no-distribution'
    if ($attempt.Success) {
        if ($attempt.RestartRequired -or $featureState.RestartRequired) {
            Complete-WslInstallLater -Reason 'L installation WSL demande encore un redemarrage Windows.'
        }
        return
    }

    if ($attempt.UnsupportedSwitch) {
        Write-Info "L option --no-distribution n est pas supportee. Nouvelle tentative avec 'wsl --install'."
        $legacyAttempt = Invoke-WslInstallFlow -Arguments @('--install') -Label 'wsl.exe --install'
        if ($legacyAttempt.Success) {
            if ($legacyAttempt.RestartRequired -or $featureState.RestartRequired) {
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

    if ($attempt.Details) {
        throw "Installation automatique de WSL echouee :`n$($attempt.Details)"
    }

    throw 'Installation automatique de WSL echouee.'
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
