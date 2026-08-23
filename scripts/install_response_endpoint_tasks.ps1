param(
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$QuietWardDatabase,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'

function Quote-Arg([string]$Value) {
    return '"' + ($Value -replace '"','\"') + '"'
}

$config = (Resolve-Path -LiteralPath $ConfigPath).Path
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
    throw "Response agent config file does not exist"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
if ($null -eq $pythonCommand) {
    $pythonCommand = Get-Command python -ErrorAction Stop
}
$python = $pythonCommand.Source

# Keep the task current-user and limited. The private config path is the only
# credential-related value placed in task metadata; the secret itself is never
# included in the command line or task definition.
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 10 `
    -RestartInterval (New-TimeSpan -Minutes 1)
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

$poller = Join-Path $repoRoot 'scripts\poll_response_agent.py'
$agentArgs = (@(
    (Quote-Arg $poller),
    '--config',
    (Quote-Arg $config),
    '--interval-seconds',
    '5'
) -join ' ')
$agentAction = New-ScheduledTaskAction -Execute $python -Argument $agentArgs -WorkingDirectory $repoRoot
Register-ScheduledTask `
    -TaskName 'QuietWard Response Agent' `
    -Action $agentAction `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description 'Capability-aware QuietWard Response endpoint agent.' `
    -Force | Out-Null

$tasks = @('QuietWard Response Agent')

if ($QuietWardDatabase) {
    $database = (Resolve-Path -LiteralPath $QuietWardDatabase).Path
    if (-not (Test-Path -LiteralPath $database -PathType Leaf)) {
        throw "QuietWard database file does not exist"
    }
    $adapter = Join-Path $repoRoot 'scripts\forward_quietward_events.py'
    $adapterArgs = (@(
        (Quote-Arg $adapter),
        '--config',
        (Quote-Arg $config),
        '--quietward-db',
        (Quote-Arg $database),
        '--interval-seconds',
        '5'
    ) -join ' ')
    $adapterAction = New-ScheduledTaskAction -Execute $python -Argument $adapterArgs -WorkingDirectory $repoRoot
    Register-ScheduledTask `
        -TaskName 'QuietWard Response Adapter' `
        -Action $adapterAction `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description 'Read-only QuietWard event adapter for QuietWard Response.' `
        -Force | Out-Null
    $tasks += 'QuietWard Response Adapter'
}

if (-not $NoStart) {
    foreach ($task in $tasks) {
        Start-ScheduledTask -TaskName $task
    }
}

$tasks | ForEach-Object { Write-Output $_ }
