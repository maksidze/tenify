param([string]$PreserveStartupState)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lab/DirectLaunchLifecycle/Lifecycle.ps1')
$gate=New-Object Threading.Mutex($false,'Local\Windows10MaximumLaunch');$held=$false
try{
 $until=[DateTime]::UtcNow.AddSeconds(60)
 do{
  Cancel-PendingDirectStartups -PreserveStartupState $PreserveStartupState
  try{$held=$gate.WaitOne(100)}catch [Threading.AbandonedMutexException]{$held=$true}
  if(!$held -and [DateTime]::UtcNow -ge $until){throw 'Direct startup cancellation cleanup is still pending.'}
 }while(!$held)
$errorsFound=@()
$actions=@(
 @('Lab\SettingsNoVfsSessionCompat\active-session.txt','Lab\SettingsNoVfsSessionCompat\Disable-Settings10-NoVFS.ps1'),
 @('Lab\StartSessionCompat\active-session.txt','Lab\StartSessionCompat\Stop-Start10-Session.ps1'),
 @('Lab\NetworkTrayUntilStopCompat\active-network-session.txt','Lab\NetworkTrayUntilStopCompat\Stop-NetworkTrayUntilStop.ps1'),
 @('Lab\DisplayMonitorPublisher\untilstop-current-state.txt','Lab\DisplayMonitorPublisher\Stop-MonitorPublisherUntilStop.ps1'))
foreach($a in $actions){if(Test-Path -LiteralPath (Join-Path $PSScriptRoot $a[0])){try{& (Join-Path $PSScriptRoot $a[1])|Out-Host}catch{$errorsFound+=@($_.Exception.Message);Write-Warning $_.Exception.Message}}}
if($errorsFound.Count){throw ($errorsFound -join '; ')}
}finally{if($held){$gate.ReleaseMutex()};$gate.Dispose()}
