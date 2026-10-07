param([string]$StartupState,[string]$FixtureBase,[string]$Directory,[string]$Mode='wait')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lifecycle.ps1')
$script:DirectLifecycleBase=$FixtureBase
$lease=$null;$result=@{Mode=$Mode;Transition=$false;Refused=$false}
try{
 $lease=Open-DirectStartup $StartupState;Assert-DirectStartup $lease
 if($Mode -eq 'fail-before-ready'){throw 'Simulated own preflight failure'}
 Invoke-DirectStartupTransition $lease {Write-DirectMarkerJson $lease.State.PreflightFile @{Fixture=$true;Launcher=$PID}}
 if($Mode -eq 'foreign-parent'){
  try{Approve-DirectTransition $lease;throw 'Child approved parent transition'}catch{if($_.Exception.Message -notlike '*exact startup parent*'){throw};$result.Refused=$true}
 }else{
  Wait-DirectTransitionApproval $lease
  Invoke-DirectStartupTransition $lease {[IO.File]::WriteAllText((Join-Path $Directory 'transition'),'Own marker only')}
  $result.Transition=$true
 }
}catch{$result.Refused=$true;$result.Error=$_.Exception.Message}
finally{
 if($lease){$lease.Parent.Dispose()}
 Write-DirectMarkerJson (Join-Path $Directory 'result.json') $result
}
