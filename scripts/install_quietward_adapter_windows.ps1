param(
    [string]$AgentConfigFile = "$env:LOCALAPPDATA\QuietWardResponse\agent.json",
    [string]$AdapterConfigFile = "$env:LOCALAPPDATA\QuietWardResponse\adapter.json",
    [string]$QuietWardDatabase = "$env:LOCALAPPDATA\QuietWard\state\quietward.sqlite3",
    [string]$TaskName = "QuietWard Response Adapter"
)

$ErrorActionPreference = "Stop"

$agentConfig = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($AgentConfigFile))
$adapterConfig = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($AdapterConfigFile))
$database = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($QuietWardDatabase))
foreach ($path in @($agentConfig, $database)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required file does not exist: $path"
    }
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Required file must not be a reparse point/symlink: $path"
    }
}

$python = (Get-Command python.exe -ErrorAction Stop).Source
$runtime = Join-Path $env:LOCALAPPDATA "QuietWardResponse\agent-runtime"
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path -Parent $adapterConfig) -Force | Out-Null

# Derive an event-ingestion-only subkey. adapter.json deliberately contains no
# Response action/polling secret.
& $python (Join-Path $PSScriptRoot 'provision_quietward_adapter.py') `
    --agent-config $agentConfig `
    --adapter-config $adapterConfig `
    --force | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "QuietWard adapter credential provisioning failed"
}

$runtimeFiles = @(
    "forward_quietward_events.py",
    "quietward_adapter_credentials.py"
)
foreach ($file in $runtimeFiles) {
    $source = Join-Path $PSScriptRoot $file
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing adapter runtime file: $source"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $runtime $file) -Force
}

$adapter = Join-Path $runtime "forward_quietward_events.py"
& $python $adapter --config $adapterConfig --quietward-db $database --once | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "QuietWard adapter validation failed"
}

$action = New-ScheduledTaskAction -Execute $python -Argument ('"{0}" --config "{1}" --quietward-db "{2}"' -f $adapter, $adapterConfig, $database)
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 20 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Read-only QuietWard event adapter for QuietWard Response" `
    -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

$task = Get-ScheduledTask -TaskName $TaskName
if ($task.Principal.RunLevel -ne "Limited") {
    throw "QuietWard adapter task was not registered with limited run level"
}

echo "QuietWard Response adapter task installed."
echo "Task: $TaskName"
echo "QuietWard database (read-only): $database"
echo "Adapter credential (event-only): $adapterConfig"
