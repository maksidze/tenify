$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lab/DirectLaunchLifecycle/Lifecycle.ps1')
$gates=Enter-DirectRestoreGates
try{
$stateRoot=Join-Path $PSScriptRoot 'state-direct'
$requested=0
if(Test-Path -LiteralPath $stateRoot){
 foreach($run in Get-ChildItem -LiteralPath $stateRoot -Directory){
  $statusFile=Join-Path $run.FullName 'status.json'
  if(-not(Test-Path -LiteralPath $statusFile)){continue}
  try{$status=Read-DirectSharedJson $statusFile}catch{continue}
  if($status.preflight -or $status.status -ne 'running'){continue}
  # Each helper consumes only the stop file in its own run directory.
  New-Item -ItemType File -Path (Join-Path $run.FullName 'stop') -Force | Out-Null
  $requested++
 }
}
Write-Host "Stop requested for $requested direct run(s). The running controller handles native Explorer recovery."
}finally{Exit-DirectRestoreGates $gates}
