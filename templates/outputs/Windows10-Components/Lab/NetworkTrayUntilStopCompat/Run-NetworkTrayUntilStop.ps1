param([switch]$Execute,[uint32]$TargetPid,[uint64]$TargetBorn,[ValidateRange(15,90)][int]$BootstrapSeconds=30)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'Windows PowerShell 5 Desktop required.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Raw | ConvertFrom-Json
foreach($item in $manifest.Files){if((Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $item.SHA256){throw ('Build changed: '+$item.Path)}}
if(!$Execute){throw 'Controller requires explicit Execute; use Ensure script for preflight/start.'}
$expected=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Runtime\Explorer10\explorer.exe'))
$target=Get-Process -Id $TargetPid
if($target.Path -ne $expected -or [uint64]$target.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $TargetBorn){throw 'Exact old Explorer identity differs.'}
if(!('Explorer10Publisher.JobChild' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot '..\DisplayMonitorPublisher\PublisherJobGuard.cs')}
$record=Join-Path $PSScriptRoot ('run-'+[guid]::NewGuid().ToString('N'))
$child=$null
try{
 $arguments=[string[]]@('--until-stop',[string]$TargetPid,[string]$TargetBorn,$expected,[string]$BootstrapSeconds,($record+'.stop'),($record+'.ready'),($record+'.log'),(Join-Path $PSScriptRoot '..\NetworkTrayCompat\pnidui.dll'))
 $child=[Explorer10Publisher.JobChild]::Start((Join-Path $PSScriptRoot 'NetworkTrayUntilStop.exe'),$arguments)
 [pscustomobject]@{Mode='UntilStop';ManifestSHA256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'manifest.json')).Hash;ControllerPath=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName;TargetPid=$TargetPid;TargetBorn=[string]$TargetBorn;ChildPid=$child.Pid;ChildBorn=[string]$child.BirthFileTime;ChildPath=(Join-Path $PSScriptRoot 'NetworkTrayUntilStop.exe');ControllerPid=$PID;ControllerBorn=[string][Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc();StopFile=($record+'.stop');Ready=($record+'.ready');VisualVerified=$false;NoShellTermination=$true}|ConvertTo-Json|Set-Content -LiteralPath ($record+'.json') -Encoding UTF8
 $pointer=Join-Path $PSScriptRoot 'active-network-session.txt'
 $temp=$record+'.pointer.tmp'
 [IO.File]::WriteAllText($temp,($record+'.json'))
 [IO.File]::Move($temp,$pointer) # Publish only a complete pointer after the immutable record is closed.
 while(!$child.WaitForExit(1000)){} # Job retained until exact child exits, no hour deadline.
 Write-Output ('Network SSO exit='+$child.ExitCode+'; '+$record+'.log')
 if($child.ExitCode){throw 'Network SSO declined/failed. See own log.'}
}finally{if($child){try{$child.StopAndWait(5000)|Out-Null}finally{$child.Dispose()}}}
