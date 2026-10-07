param([switch]$InventoryOnly,[switch]$Execute,[uint32]$TargetPid,[uint64]$TargetBorn,[ValidateRange(1,3600)][int]$Seconds=3600)
$ErrorActionPreference='Stop'
$manifest=Get-Content (Join-Path $PSScriptRoot 'manifest.json') -Raw | ConvertFrom-Json
foreach($item in $manifest.Files){
 if((Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $item.Sha256){throw ('Verified build changed: '+$item.Path)}
}
$exe=Join-Path $PSScriptRoot 'MonitorPublisher.exe'
$jobSource=Join-Path $PSScriptRoot 'PublisherJobGuard.cs'
if(-not ('Explorer10Publisher.JobChild' -as [type])){Add-Type -Path $jobSource}
$report=Join-Path $PSScriptRoot ('publisher-'+[guid]::NewGuid().ToString('N')+'.log')
if($InventoryOnly){& $exe --inventory $report;if($LASTEXITCODE){throw ('Inventory refused: '+$LASTEXITCODE+'; '+$report)};Write-Output $report;return}
if(-not $Execute){throw 'Prepared only. Root must authorize actual stock conversation publication with -Execute.'}
if(-not $TargetPid -or -not $TargetBorn){throw 'Provide exact shell PID and FILETIME process birth, never a process name.'}
$target=Get-Process -Id $TargetPid
$expectedPath=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Runtime\Explorer10\explorer.exe'))
if($target.Path -ne $expectedPath -or [uint64]$target.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $TargetBorn){throw 'Old Explorer identity mismatch.'}
# Native Taskbar.dll is the stock server owner; never duplicate it in this shell.
if(@($target.Modules | Where-Object {$_.ModuleName -ieq 'Taskbar.dll'}).Count){throw 'Native taskbar is loaded; publisher refused.'}
$mutex=New-Object Threading.Mutex($false,'Local\Explorer10DisplayMonitorPublisher')
$owned=$false;$child=$null
try{
 try{$owned=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$owned=$true}
 if(-not $owned){throw 'Another owned publisher is active.'}
 $childArgs=[string[]]@('--run',$report,[string]$TargetPid,[string]$TargetBorn,$expectedPath,[string]$Seconds)
 $child=[Explorer10Publisher.JobChild]::Start($exe,$childArgs)
 # Server release synchronously marshals dispatcher cleanup. Bound the entire child lifetime.
 if(-not $child.WaitForExit(($Seconds+10)*1000)){$child.StopAndWait(5000)|Out-Null;throw ('Publisher cleanup timed out; exact owned job terminated. '+$report)}
 [pscustomobject]@{Report=$report;PublisherPid=$child.Pid;PublisherBirth=[string]$child.BirthFileTime;AssignedBeforeResume=$child.AssignedBeforeResume;ExitCode=$child.ExitCode;TargetPid=$TargetPid;NoShellTermination=$true;Seconds=$Seconds}|ConvertTo-Json|Set-Content ($report+'.state.json')
 if($child.ExitCode){throw ('Publisher failed/declined: '+$child.ExitCode+'; '+$report)}
 Write-Output $report
}finally{
 # Close the owned job before releasing the single-run mutex, even on exception.
 try{if($child){try{$child.StopAndWait(5000)|Out-Null}finally{$child.Dispose()}}}
 finally{if($owned){$mutex.ReleaseMutex()};$mutex.Dispose()}
}
