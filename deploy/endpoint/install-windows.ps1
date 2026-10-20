#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$Config,
    [Parameter(Mandatory=$true)][string]$PublisherThumbprint,
    [switch]$Activate
)
$ErrorActionPreference='Stop'
if (!$Activate) { throw 'Use -Activate only after reviewing the device-wide firewall plan.' }
$Signature=Get-AuthenticodeSignature -LiteralPath $Binary
if ($Signature.Status -ne 'Valid' -or $Signature.SignerCertificate.Thumbprint -ne $PublisherThumbprint) { throw 'Agent must have a valid signature from the pinned publisher.' }
$BinRoot=Join-Path $env:ProgramFiles 'WhatsThePoint'
$DataRoot=Join-Path $env:ProgramData 'WhatsThePoint'
$StateRoot=Join-Path $DataRoot 'Endpoint'
if (Get-ScheduledTask -TaskName 'WhatsThePointEndpoint' -ErrorAction SilentlyContinue) { throw 'Endpoint already installed.' }
foreach ($Target in @($BinRoot,$StateRoot)) {
    $Path=$Target
    while ($Path) {
        if (Test-Path -LiteralPath $Path) {
            $Item=Get-Item -LiteralPath $Path
            if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point rejected: $Path" }
        }
        $Path=Split-Path -Parent $Path
    }
}
if ((Test-Path -LiteralPath $BinRoot) -or (Test-Path -LiteralPath $DataRoot)) { throw 'Destination already exists. Review/remove the previous installation before enrolling.' }
New-Item -ItemType Directory -Force -Path $BinRoot,$StateRoot | Out-Null
foreach ($Path in @($BinRoot,$DataRoot,$StateRoot)) {
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
    if ($LASTEXITCODE) { throw 'Could not protect managed paths.' }
}
$Agent=Join-Path $BinRoot 'wtp-agent.exe'
Copy-Item -LiteralPath $Binary -Destination $Agent
Copy-Item -LiteralPath $Config -Destination (Join-Path $StateRoot 'config.json')
$Action=New-ScheduledTaskAction -Execute $Agent -Argument "run --config `"$StateRoot\config.json`" --state-dir `"$StateRoot`""
$Principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$Settings=New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'WhatsThePointEndpoint' -Action $Action -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $Principal -Settings $Settings -Description 'Signed endpoint firewall supervisor' | Out-Null
Start-ScheduledTask -TaskName 'WhatsThePointEndpoint'
Write-Host 'SYSTEM supervisor installed. Confirm the portal heartbeat. Reboot after initial activation to discard pre-existing connections.'
