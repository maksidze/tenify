param([switch]$Execute,[uint32]$TargetPid,[uint64]$TargetBorn,[ValidateRange(5,90)][int]$BootstrapSeconds=30)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Windows PowerShell 5 required.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
if(!$Execute){throw 'Prepared only; -Execute is required for publication.'}
$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'untilstop-manifest.json') -Raw|ConvertFrom-Json
foreach($item in $manifest.Files){if((Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $item.Sha256){throw ('UntilStop build changed: '+$item.Path)}}
if(!$TargetPid -or !$TargetBorn){throw 'Provide exact old shell PID and birth.'}
$target=Get-Process -Id $TargetPid
$path=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Runtime\Explorer10\explorer.exe'))
if($target.Path -ine $path -or [uint64]$target.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $TargetBorn){throw 'Shell identity differs.'}
if(@($target.Modules|Where-Object{$_.ModuleName -ieq 'Taskbar.dll'}).Count){throw 'Native taskbar owns the stock publisher; refused.'}
if(-not ('Explorer10Publisher.JobChild' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'PublisherJobGuard.cs')}
$nonce=[guid]::NewGuid().ToString('N');$report=Join-Path $PSScriptRoot ('publisher-untilstop-'+$nonce+'.log');$cancel=$report+'.cancel';$statePath=$report+'.state.json'
$owner=Get-Process -Id $PID
$state=[ordered]@{Mode='UntilStop';Status='starting';Report=$report;CancelFile=$cancel;ControllerPid=$PID;ControllerBorn=[string]$owner.StartTime.ToUniversalTime().ToFileTimeUtc();TargetPid=$TargetPid;TargetBorn=[string]$TargetBorn;TargetPath=$path;PublisherPid=$null;PublisherBorn=$null;BootstrapSeconds=$BootstrapSeconds;StallBoundSeconds=15;CleanupBoundSeconds=10}
function Save-State{$state|ConvertTo-Json|Set-Content -LiteralPath $statePath -Encoding UTF8}
function Read-SharedLog {$stream=[IO.File]::Open($report,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);try{$reader=New-Object IO.StreamReader($stream);try{return $reader.ReadToEnd()}finally{$reader.Dispose()}}finally{$stream.Dispose()}}
$mutex=New-Object Threading.Mutex($false,'Local\Explorer10DisplayMonitorPublisher');$held=$false;$child=$null
try{
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){throw 'Another owned monitor publisher is active.'}
 Save-State
 $arguments=[string[]]@('--until-stop',$report,[string]$TargetPid,[string]$TargetBorn,$path,$cancel,[string]$PID,$state.ControllerBorn,[string]$BootstrapSeconds)
 $child=[Explorer10Publisher.JobChild]::Start((Join-Path $PSScriptRoot 'MonitorPublisherUntilStop.exe'),$arguments)
 $state.PublisherPid=$child.Pid;$state.PublisherBorn=[string]$child.BirthFileTime;Save-State
 [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'untilstop-current-state.txt'),$statePath)
 while(!$child.WaitForExit(250)){
  if($state.Status -eq 'starting' -and (Test-Path -LiteralPath $report) -and ((Read-SharedLog) -match 'UNTIL_STOP ready')){$state.Status='running';Save-State}
 }
 $state.ExitCode=$child.ExitCode;$state.Status=if($child.ExitCode -eq 0){'stopped'}else{'failed'};Save-State
 if($child.ExitCode){throw ('UntilStop publisher failed: '+$child.ExitCode+'; '+$report)}
 Write-Output $statePath
}finally{
 [IO.File]::WriteAllText($cancel,'Controller cleanup requested')
 try{if($child){try{if(!$child.WaitForExit(12000)){$child.StopAndWait(5000)|Out-Null}}finally{$child.Dispose()}}}
 finally{if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
}
