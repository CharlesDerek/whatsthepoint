#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$Binary = 'C:\Program Files\WhatsThePoint\wtp.exe',
    [string]$DataRoot = 'C:\ProgramData\WhatsThePoint'
)
$ErrorActionPreference = 'Stop'
$Binary = (Resolve-Path -LiteralPath $Binary).Path
$DataRoot = (Resolve-Path -LiteralPath $DataRoot).Path
$Config = Join-Path $DataRoot 'wtp.toml'
if (!(Test-Path -LiteralPath $Config)) { throw "Missing $Config" }
if (!(Test-Path -LiteralPath (Join-Path $DataRoot 'data\wtp.db'))) {
    throw "Run wtp --data-dir `"$DataRoot\data`" init before registering the task."
}
if (Get-ScheduledTask -TaskName 'WhatsThePoint' -ErrorAction SilentlyContinue) {
    throw 'Task already exists. Stop and unregister it before reinstalling.'
}
# Restrict configuration, database, WAL files, and future children.
& icacls.exe $DataRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the data directory ACL.' }
$Action = New-ScheduledTaskAction -Execute $Binary -Argument "--config `"$Config`" --data-dir `"$DataRoot\data`" serve" -WorkingDirectory $DataRoot
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName 'WhatsThePoint' -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description 'What’s the Point DNS filter'
Start-ScheduledTask -TaskName 'WhatsThePoint'
Write-Host 'Task started. Verify DNS before changing adapter settings. Console: http://127.0.0.1:8080'
