# Embedded by wtp-agent after a typed, signed network policy has been validated.
# Device-wide exclusive firewall management: use dedicated managed endpoints.
$ErrorActionPreference = 'Stop'
$Group = 'WhatsThePoint.Endpoint'
$Backup = Join-Path $StateDir 'windows-firewall-before.json'
function Get-OutsideAllows {
    @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow |
        Where-Object { $_.Group -ne $Group })
}
function Restore-WtpFirewall {
    if (!(Test-Path -LiteralPath $Backup)) { throw 'Missing firewall rollback snapshot.' }
    $Before = Get-Content -LiteralPath $Backup -Raw | ConvertFrom-Json
    Get-NetFirewallRule -PolicyStore PersistentStore -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    foreach ($Name in $Before.enabledAllows) {
        Get-NetFirewallRule -PolicyStore PersistentStore -Name $Name -ErrorAction SilentlyContinue | Enable-NetFirewallRule
    }
    foreach ($Profile in $Before.profiles) {
        Set-NetFirewallProfile -PolicyStore PersistentStore -Name $Profile.Name -Enabled $Profile.Enabled -DefaultInboundAction $Profile.DefaultInboundAction -DefaultOutboundAction $Profile.DefaultOutboundAction
    }
}
if ($Mode -eq 'Rollback') { Restore-WtpFirewall; Write-Output 'restored'; exit 0 }
if ($Mode -eq 'Check') {
    $Profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if (@($Profiles | Where-Object { $_.Enabled -ne 'True' -or $_.DefaultOutboundAction -ne 'Block' -or $_.DefaultInboundAction -ne 'Block' }).Count) { throw 'Firewall profile drift detected.' }
    if (@($Profiles | Where-Object { $_.DisabledInterfaceAliases.Count -and $_.DisabledInterfaceAliases -ne 'NotConfigured' }).Count) { throw 'Firewall is disabled on an interface.' }
    if ((Get-OutsideAllows).Count) { throw 'An outside allow rule can bypass endpoint policy.' }
    $Rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group $Group | Sort-Object Name)
    if (!$Rules.Count -or @($Rules | Where-Object { $_.Enabled -ne 'True' }).Count) { throw 'Endpoint rules missing or disabled.' }
    $Rules | ForEach-Object {
        $Address = $_ | Get-NetFirewallAddressFilter
        $Port = $_ | Get-NetFirewallPortFilter
        $Interface = $_ | Get-NetFirewallInterfaceFilter
        [ordered]@{name=$_.Name;direction=[string]$_.Direction;action=[string]$_.Action;remote=$Address.RemoteAddress;protocol=[string]$Port.Protocol;port=$Port.RemotePort;localPort=$Port.LocalPort;icmp=$Port.IcmpType;interfaces=$Interface.InterfaceAlias}
    } | ConvertTo-Json -Depth 6 -Compress
    exit 0
}
if ($Mode -ne 'Apply') { throw 'Invalid firewall operation.' }
foreach ($Interface in $Policy.interfaces) {
    if (!(Get-NetAdapter -Name $Interface -Physical -ErrorAction SilentlyContinue)) { throw "Approved physical adapter missing: $Interface" }
}
if (@(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.DisabledInterfaceAliases.Count -and $_.DisabledInterfaceAliases -ne 'NotConfigured' }).Count) { throw 'Remove firewall interface exemptions before installation.' }
$Outside = Get-OutsideAllows
# Rules delivered by GPO/MDM must be removed at their source; do not claim local overrides win.
if (@($Outside | Where-Object { $_.PolicyStoreSourceType -ne 'Local' }).Count) { throw 'Nonlocal allow rules conflict with exclusive endpoint enforcement.' }
if (!(Test-Path -LiteralPath $Backup)) {
    $Snapshot = [ordered]@{
        profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | Select-Object Name,@{N='Enabled';E={[string]$_.Enabled}},@{N='DefaultInboundAction';E={[string]$_.DefaultInboundAction}},@{N='DefaultOutboundAction';E={[string]$_.DefaultOutboundAction}})
        enabledAllows = @($Outside | Select-Object -ExpandProperty Name)
    }
    $Snapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Backup -Encoding UTF8
}
# Drop the old permits before adding replacements. A failed change stays closed.
Set-NetFirewallProfile -PolicyStore PersistentStore -Name Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
foreach ($Rule in $Outside) { Disable-NetFirewallRule -PolicyStore PersistentStore -Name $Rule.Name }
Get-NetFirewallRule -PolicyStore PersistentStore -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$Index = 0
foreach ($Protocol in @('TCP','UDP')) {
    $Endpoints = if ($Protocol -eq 'TCP') { $Policy.tcp } else { $Policy.udp }
    foreach ($Endpoint in $Endpoints) {
        $Index++
        New-NetFirewallRule -PolicyStore PersistentStore -Name "WTP-Endpoint-$Index" -DisplayName "WTP approved $Protocol endpoint $Index" -Group $Group -Direction Outbound -Action Allow -Enabled True -Profile Any -Protocol $Protocol -RemoteAddress $Endpoint.address -RemotePort $Endpoint.port -InterfaceAlias $Policy.interfaces | Out-Null
    }
}
if ($Policy.dhcp) {
    New-NetFirewallRule -PolicyStore PersistentStore -Name 'WTP-Endpoint-DHCP4-In' -DisplayName 'WTP DHCP v4 replies' -Group $Group -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol UDP -LocalPort 68 -RemotePort 67 -InterfaceAlias $Policy.interfaces | Out-Null
    New-NetFirewallRule -PolicyStore PersistentStore -Name 'WTP-Endpoint-DHCP6-In' -DisplayName 'WTP DHCP v6 replies' -Group $Group -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol UDP -LocalPort 546 -RemotePort 547 -RemoteAddress 'fe80::/10' -InterfaceAlias $Policy.interfaces | Out-Null
    New-NetFirewallRule -PolicyStore PersistentStore -Name 'WTP-Endpoint-DHCP4' -DisplayName 'WTP DHCP v4' -Group $Group -Direction Outbound -Action Allow -Enabled True -Profile Any -Protocol UDP -LocalPort 68 -RemotePort 67 -InterfaceAlias $Policy.interfaces | Out-Null
    New-NetFirewallRule -PolicyStore PersistentStore -Name 'WTP-Endpoint-DHCP6' -DisplayName 'WTP DHCP v6' -Group $Group -Direction Outbound -Action Allow -Enabled True -Profile Any -Protocol UDP -LocalPort 546 -RemotePort 547 -RemoteAddress 'ff02::1:2' -InterfaceAlias $Policy.interfaces | Out-Null
}
New-NetFirewallRule -PolicyStore PersistentStore -Name 'WTP-Endpoint-ND-Out' -DisplayName 'WTP IPv6 neighbor discovery outbound' -Group $Group -Direction Outbound -Action Allow -Enabled True -Profile Any -Protocol ICMPv6 -IcmpType 133,134,135,136 -RemoteAddress Any -InterfaceAlias $Policy.interfaces | Out-Null
New-NetFirewallRule -PolicyStore PersistentStore -Name 'WTP-Endpoint-ND-In' -DisplayName 'WTP IPv6 neighbor discovery inbound' -Group $Group -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol ICMPv6 -IcmpType 133,134,135,136 -RemoteAddress Any -InterfaceAlias $Policy.interfaces | Out-Null
Write-Output 'applied'
