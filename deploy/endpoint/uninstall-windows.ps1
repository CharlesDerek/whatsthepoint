#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
Stop-ScheduledTask -TaskName 'WhatsThePointEndpoint'
Unregister-ScheduledTask -TaskName 'WhatsThePointEndpoint' -Confirm:$false
& "$env:ProgramFiles\WhatsThePoint\wtp-agent.exe" rollback --state-dir "$env:ProgramData\WhatsThePoint\Endpoint"
if ($LASTEXITCODE) { throw 'Rollback failed; retain the firewall backup and inspect the agent log.' }
Write-Host 'Original firewall profile defaults and original local allow rules restored. Managed files retained.'
