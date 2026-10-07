# Scoped direct-launch support. This does not start or change any process on import.
$script:DirectLifecycleLab=$PSScriptRoot
$script:DirectLifecycleBase=Split-Path (Split-Path $PSScriptRoot)
foreach($moduleName in 'Utility','Management','Security'){Import-Module (Join-Path $PSHOME ('Modules/Microsoft.PowerShell.'+$moduleName+'/Microsoft.PowerShell.'+$moduleName+'.psd1')) -ErrorAction Stop}
if(-not ('DirectLaunchLifecycle.Identity' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'Identity.cs')}
if(-not ('DirectLaunchLifecycle.OwnedJobProcess' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'OwnedJobProcess.cs')}
function Start-DirectOwnedJob {
 param([string]$FilePath,[string[]]$ArgumentList=@(),[string]$RedirectStandardOutput,[string]$RedirectStandardError,[string]$WorkingDirectory=$script:DirectLifecycleBase,[switch]$BreakawayChildren)
 [DirectLaunchLifecycle.OwnedJobProcess]::Start($FilePath,$ArgumentList,$RedirectStandardOutput,$RedirectStandardError,$WorkingDirectory,[bool]$BreakawayChildren)
}
function New-DirectStartup {
 param([int]$Seconds=180)
 $id=[DirectLaunchLifecycle.Identity]::Open([uint32]$PID,0,$null,$false)
 try{
  $dir=Join-Path $script:DirectLifecycleBase ('state-direct-launch/'+[Guid]::NewGuid().ToString('N'))
  [IO.Directory]::CreateDirectory($dir)|Out-Null
  $s=[ordered]@{Version=2;Directory=$dir;Parent=@{Pid=$id.Pid;Birth=[string]$id.Birth;Path=$id.Path};DeadlineTick=([DirectLaunchLifecycle.Identity]::GetTickCount64()+[uint64]($Seconds*1000));CancelFile=(Join-Path $dir 'cancel');CommitFile=(Join-Path $dir 'committed');ReadyFile=(Join-Path $dir 'ready.json');TerminalFile=(Join-Path $dir 'terminal.json');PreflightFile=(Join-Path $dir 'preflight-ready.json');ContinueFile=(Join-Path $dir 'transition-continue.json')}
  $file=Join-Path $dir 'startup.json';$temporary=$file+'.pending';[IO.File]::WriteAllText($temporary,($s|ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)));[IO.File]::Move($temporary,$file);return $file
 }finally{$id.Dispose()}
}
function Open-DirectStartup {
 param([string]$Path)
 $root=[IO.Path]::GetFullPath((Join-Path $script:DirectLifecycleBase 'state-direct-launch'))+'\'
 $full=[IO.Path]::GetFullPath($Path)
 if(!$full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -ne 'startup.json'){throw 'Invalid direct startup record path.'}
 $s=Read-DirectSharedJson $full
 if($s.Version -ne 2){throw 'Unsupported direct startup record version.'}
 if([IO.Path]::GetFullPath($s.Directory) -ine [IO.Path]::GetDirectoryName($full)){throw 'Startup record directory mismatch.'}
 foreach($pair in @(@('CancelFile','cancel'),@('CommitFile','committed'),@('ReadyFile','ready.json'),@('TerminalFile','terminal.json'),@('PreflightFile','preflight-ready.json'),@('ContinueFile','transition-continue.json'))){if($s.($pair[0]) -ine (Join-Path $s.Directory $pair[1])){throw 'Startup record marker mismatch.'}}
 $parent=[DirectLaunchLifecycle.Identity]::Open([uint32]$s.Parent.Pid,[uint64]$s.Parent.Birth,[string]$s.Parent.Path,$false)
 return @{State=$s;Parent=$parent;Path=$full}
}
function Assert-DirectStartup {
 param($Lease)
 $s=$Lease.State
 if(Test-Path -LiteralPath $s.CancelFile){throw 'Direct startup cancelled.'}
 if(Test-Path -LiteralPath $s.CommitFile){return}
 if(!$Lease.Parent.Alive){throw 'Exact startup parent exited.'}
 if([DirectLaunchLifecycle.Identity]::GetTickCount64() -ge [uint64]$s.DeadlineTick){throw 'Direct startup deadline expired.'}
}
function Cancel-DirectStartup {
 param($Lease,[string]$Reason='Caller cancelled direct startup')
 $gate=New-Object Threading.Mutex($false,('Local\DirectStartupTransition_'+[IO.Path]::GetFileName($Lease.State.Directory)));$held=$false
 try{try{$held=$gate.WaitOne(10000)}catch [Threading.AbandonedMutexException]{$held=$true};if(!$held){throw 'Startup transition still pending; cancellation gate timeout.'};[IO.File]::WriteAllText($Lease.State.CancelFile,$Reason)}
 finally{if($held){$gate.ReleaseMutex()};$gate.Dispose()}
}
function Invoke-DirectStartupTransition {
 param($Lease,[scriptblock]$Action)
 $gate=New-Object Threading.Mutex($false,('Local\DirectStartupTransition_'+[IO.Path]::GetFileName($Lease.State.Directory)));$held=$false
 try{try{$held=$gate.WaitOne(10000)}catch [Threading.AbandonedMutexException]{$held=$true};if(!$held){throw 'Startup transition gate timeout.'};Assert-DirectStartup $Lease;& $Action}
 finally{if($held){$gate.ReleaseMutex()};$gate.Dispose()}
}
function Commit-DirectStartup {
 param($Lease)
 Invoke-DirectStartupTransition $Lease {[IO.File]::WriteAllText($Lease.State.CommitFile,'Exact shell accepted; no total lifetime deadline')}
}
function Write-DirectMarkerJson {
 param([string]$Path,$Value)
 # Markers are single-publication, never mutable status files.
 $temporary=$Path+'.pending';[IO.File]::WriteAllText($temporary,($Value|ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)));[IO.File]::Move($temporary,$Path)
}
function Assert-DirectStartupParent {
 param($Lease)
 Assert-DirectStartup $Lease
 if($Lease.Parent.Pid -ne [uint32]$PID){throw 'Only the exact startup parent may approve this transition.'}
}
function Approve-DirectTransition {
 param($Lease)
 Assert-DirectStartupParent $Lease
 Invoke-DirectStartupTransition $Lease {
  if(!(Test-Path -LiteralPath $Lease.State.PreflightFile)){throw 'Preflight readiness must precede transition approval.'}
  $value=@{Version=1;Parent=$Lease.State.Parent;PreflightSHA256=(Get-FileHash -LiteralPath $Lease.State.PreflightFile).Hash}
  Write-DirectMarkerJson $Lease.State.ContinueFile $value
 }
}
function Wait-DirectTransitionApproval {
 param($Lease)
 while(!(Test-Path -LiteralPath $Lease.State.ContinueFile)){Assert-DirectStartup $Lease;Start-Sleep -Milliseconds 50}
 Invoke-DirectStartupTransition $Lease {
  $ack=Read-DirectSharedJson $Lease.State.ContinueFile
  if($ack.Version -ne 1 -or $ack.Parent.Pid -ne $Lease.State.Parent.Pid -or [uint64]$ack.Parent.Birth -ne [uint64]$Lease.State.Parent.Birth -or $ack.Parent.Path -ine $Lease.State.Parent.Path -or $ack.PreflightSHA256 -ine (Get-FileHash -LiteralPath $Lease.State.PreflightFile).Hash){throw 'Preflight transition approval identity differs.'}
 }
}
function Read-DirectSharedBytes {
 param([string]$Path,[int]$ExpectedLength)
 for($attempt=0;$attempt -lt 4;$attempt++){
  $stream=$null
  try{
   $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
   if($stream.Length -ne $ExpectedLength){throw 'Shared lease length differs.'}
   $bytes=New-Object byte[] $ExpectedLength;$offset=0
   while($offset -lt $ExpectedLength){$n=$stream.Read($bytes,$offset,$ExpectedLength-$offset);if(!$n){throw 'Shared lease truncated.'};$offset+=$n}
   return ,$bytes
  }catch [IO.IOException],[UnauthorizedAccessException]{if($attempt -eq 3){throw};Start-Sleep -Milliseconds 25}
  finally{if($stream){$stream.Dispose()}}
 }
}
function Read-DirectSharedJson {
 param([string]$Path)
 for($attempt=0;$attempt -lt 4;$attempt++){
  $stream=$null;$reader=$null
  try{
   $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
   if($stream.Length -gt 16777216){throw 'Oversized direct state file.'}
   $reader=New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$true)
   $text=$reader.ReadToEnd()
  }catch [IO.IOException],[UnauthorizedAccessException]{if($attempt -eq 3){throw};Start-Sleep -Milliseconds 25;continue}
  finally{if($reader){$reader.Dispose()}elseif($stream){$stream.Dispose()}}
  # Close the file before PowerShell parses JSON; parsing may be slow.
  return ($text|ConvertFrom-Json)
 }
}
function Enter-DirectRestoreGates {
 $gates=@();$held=@()
 try{
  foreach($name in @('Local\Windows10MaximumLaunch','Local\Windows10DirectShellLaunch')){
   $g=New-Object Threading.Mutex($false,$name);$gates+=@($g);$acquired=$false;$until=[DateTime]::UtcNow.AddSeconds(60)
   do{Cancel-PendingDirectStartups;try{$acquired=$g.WaitOne(100)}catch [Threading.AbandonedMutexException]{$acquired=$true};if(!$acquired -and [DateTime]::UtcNow -ge $until){throw 'Cancelled direct startup cleanup is still pending.'}}while(!$acquired)
   $held+=@($g)
  }
  return ,$held
 }catch{foreach($g in $held){$g.ReleaseMutex()};foreach($g in $gates){$g.Dispose()};throw}
}
function Exit-DirectRestoreGates {
 param($Gates)
 for($i=$Gates.Count-1;$i -ge 0;$i--){$Gates[$i].ReleaseMutex();$Gates[$i].Dispose()}
}
function Enter-DirectNativeRecoveryGate {
 param($Lease)
 $gate=New-Object Threading.Mutex($false,'Local\Explorer10NativeRecovery');$held=$false
 try{
  do{Assert-DirectStartup $Lease;try{$held=$gate.WaitOne(100)}catch [Threading.AbandonedMutexException]{$held=$true}}while(!$held)
  Assert-DirectStartup $Lease
  return $gate
 }catch{if($held){$gate.ReleaseMutex()};$gate.Dispose();throw}
}
function Cancel-PendingDirectStartups {
 param([string]$PreserveStartupState)
 $preserve=$null
 if($PreserveStartupState){
  $owned=Open-DirectStartup $PreserveStartupState
  try{Assert-DirectStartupParent $owned;$preserve=$owned.Path}finally{$owned.Parent.Dispose()}
 }
 $root=Join-Path $script:DirectLifecycleBase 'state-direct-launch'
 if(!(Test-Path -LiteralPath $root)){return}
 foreach($dir in Get-ChildItem -LiteralPath $root -Directory){
  $f=Join-Path $dir.FullName 'startup.json';if(!(Test-Path -LiteralPath $f)){continue}
  if($preserve -and [IO.Path]::GetFullPath($f) -ieq $preserve){continue}
  try{
   $s=Read-DirectSharedJson $f
   if($s.Directory -ine $dir.FullName -or $s.CancelFile -ine (Join-Path $dir.FullName 'cancel')){throw 'Pending startup path mismatch.'}
   if(!(Test-Path -LiteralPath (Join-Path $dir.FullName 'committed')) -and !(Test-Path -LiteralPath (Join-Path $dir.FullName 'terminal.json'))){Cancel-DirectStartup @{State=$s} 'Explicit stop/restore cancelled pending direct startup'}
  }catch{throw ('Cannot safely cancel pending startup '+$f+': '+$_.Exception.Message)}
 }
}
