$ErrorActionPreference='Stop'
$errorsFound=@()
$actions=@(
 @('Lab\SettingsUntilStopCompat\active-session.txt','Lab\SettingsUntilStopCompat\Disable-Settings10-UntilStop.ps1'),
 @('Lab\StartSessionCompat\active-session.txt','Lab\StartSessionCompat\Stop-Start10-Session.ps1'),
 @('Lab\NetworkTrayUntilStopCompat\active-network-session.txt','Lab\NetworkTrayUntilStopCompat\Stop-NetworkTrayUntilStop.ps1'),
 @('Lab\DisplayMonitorPublisher\untilstop-current-state.txt','Lab\DisplayMonitorPublisher\Stop-MonitorPublisherUntilStop.ps1'))
foreach($a in $actions){if(Test-Path -LiteralPath (Join-Path $PSScriptRoot $a[0])){try{& (Join-Path $PSScriptRoot $a[1])|Out-Host}catch{$errorsFound+=@($_.Exception.Message);Write-Warning $_.Exception.Message}}}
if($errorsFound.Count){throw ($errorsFound -join '; ')}
