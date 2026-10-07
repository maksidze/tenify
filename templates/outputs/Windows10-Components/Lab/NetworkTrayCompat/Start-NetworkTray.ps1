param([switch]$Execute,[uint32]$TargetPid,[uint64]$TargetBorn,[ValidateRange(15,3600)][int]$Seconds=90)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'Windows PowerShell 5 Desktop required.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Raw | ConvertFrom-Json
foreach($item in $manifest.Files){if((Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $item.SHA256){throw ('Build changed: '+$item.Path)}}
if(!$Execute){Write-Output 'Preflight hashes passed. No SSO started. Explicit -Execute and exact old-shell identity required.';return}
$expected=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Runtime\Explorer10\explorer.exe'))
$target=Get-Process -Id $TargetPid
if($target.Path -ne $expected -or [uint64]$target.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $TargetBorn){throw 'Exact old Explorer identity differs.'}
if(!('Explorer10Publisher.JobChild' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot '..\DisplayMonitorPublisher\PublisherJobGuard.cs')}
$record=Join-Path $PSScriptRoot ('run-'+[guid]::NewGuid().ToString('N'))
$child=$null
try{
 $arguments=[string[]]@('--run',[string]$TargetPid,[string]$TargetBorn,$expected,[string]$Seconds,($record+'.stop'),($record+'.ready'),($record+'.log'),(Join-Path $PSScriptRoot 'pnidui.dll'))
 $child=[Explorer10Publisher.JobChild]::Start((Join-Path $PSScriptRoot 'NetworkTrayHost.exe'),$arguments)
 [pscustomobject]@{TargetPid=$TargetPid;TargetBorn=[string]$TargetBorn;ChildPid=$child.Pid;ChildBorn=[string]$child.BirthFileTime;ChildPath=(Join-Path $PSScriptRoot 'NetworkTrayHost.exe');ControllerPid=$PID;ControllerBorn=[string][Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc();StopFile=($record+'.stop');Ready=($record+'.ready');VisualVerified=$false;NoShellTermination=$true}|ConvertTo-Json|Set-Content -LiteralPath ($record+'.json') -Encoding UTF8
 [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'active-network-session.txt'),($record+'.json'))
 if(!($child.WaitForExit($Seconds*1000) -or $child.WaitForExit(12000))){$child.StopAndWait(5000)|Out-Null;throw 'Owned helper cleanup timed out; only its job terminated.'}
 Write-Output ('Network SSO exit='+$child.ExitCode+'; '+$record+'.log')
 if($child.ExitCode){throw 'Network SSO declined/failed. See own log.'}
}finally{if($child){try{$child.StopAndWait(5000)|Out-Null}finally{$child.Dispose()}}}
