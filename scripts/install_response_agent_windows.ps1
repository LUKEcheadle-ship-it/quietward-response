param(
    [string]$ConfigFile = "$env:LOCALAPPDATA\QuietWardResponse\agent.json",
    [string]$TaskName = "QuietWard Response Agent"
)

$ErrorActionPreference = "Stop"

$config = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($ConfigFile))
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
    throw "Response agent config does not exist: $config"
}
$item = Get-Item -LiteralPath $config -Force
if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Response agent config must not be a reparse point/symlink: $config"
}
if ($item.Length -le 0 -or $item.Length -gt 65536) {
    throw "Response agent config size is invalid"
}

$pythonCommand = Get-Command python.exe -ErrorAction Stop
$python = $pythonCommand.Source
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "python.exe could not be resolved to a normal file"
}
$pythonItem = Get-Item -LiteralPath $python -Force
if ($pythonItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "python.exe must not be a reparse point/symlink"
}

$runtime = Join-Path $env:LOCALAPPDATA "QuietWardResponse\agent-runtime"
New-Item -ItemType Directory -Path $runtime -Force | Out-Null

$runtimeFiles = @(
    "poll_response_agent.py",
    "response_agent_v12.py",
    "response_agent.py",
    "response_agent_capabilities.py",
    "response_agent_file_v12.py",
    "response_agent_network.py",
    "response_agent_resources.py",
    "private_state_io.py"
)
foreach ($file in $runtimeFiles) {
    $source = Join-Path $PSScriptRoot $file
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing Response agent runtime file: $source"
    }
    $sourceItem = Get-Item -LiteralPath $source -Force
    if ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Response agent runtime file must not be a reparse point/symlink: $source"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $runtime $file) -Force
}

& $python (Join-Path $runtime "response_agent_v12.py") capabilities --config $config | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Response agent capability validation failed"
}

$poller = Join-Path $runtime "poll_response_agent.py"
$action = New-ScheduledTaskAction -Execute $python -Argument ('"{0}" --config "{1}"' -f $poller, $config)
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
    -Description "QuietWard Response capability-aware controlled-response agent" `
    -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 1
$task = Get-ScheduledTask -TaskName $TaskName
if ($task.Principal.RunLevel -ne "Limited") {
    throw "Response agent task was not registered with limited run level"
}

echo "QuietWard Response agent task installed."
echo "Task: $TaskName"
echo "Config: $config"
echo "Runtime: $runtime"
