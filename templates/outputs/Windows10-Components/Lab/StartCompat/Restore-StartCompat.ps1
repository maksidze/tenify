param([Parameter(Mandatory=$true)][string]$StatePath,[switch]$Guard)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\..\Launch-NonUiProcess.ps1')
$state=Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if($Guard){
 $deadline=[DateTime]::Parse($state.DeadlineUtc).ToUniversalTime()
 while([DateTime]::UtcNow -lt $deadline){if(Test-Path -LiteralPath ($StatePath+'.restore')){break};Start-Sleep -Milliseconds 250}
}
$mutexName='Local\StartCompatRestore_'+[IO.Path]::GetFileNameWithoutExtension($StatePath)
$mutex=New-Object Threading.Mutex($false,$mutexName)
$owned=$false
try {
 try {$owned=$mutex.WaitOne(20000)} catch [Threading.AbandonedMutexException] {$owned=$true}
 if(-not $owned){throw 'The restoration lock is held by another supervisor.'}
 if(Test-Path -LiteralPath ($StatePath+'.restored.json')){return}
if($state.PackageDebugMode -and (Test-Path -LiteralPath ($StatePath+'.restore.enabled'))){
 $disable=Start-NonUiProcess -FilePath (Join-Path $PSScriptRoot 'PackageDebugController.exe') -ArgumentList @('disable',$state.PackageFullName) -RedirectStandardOutput ($StatePath+'.disable.log') -RedirectStandardError ($StatePath+'.disable.err')
 try{$disable.WaitForExit();if($disable.ExitCode -ne 0){throw 'DisableDebugging did not succeed; native restart was not attempted.'}}finally{$disable.Dispose()}
}
$startTime=[DateTime]::Parse($state.StartUtc).ToUniversalTime()
$ownPid=0
if($state.NativePathMode -and (Test-Path -LiteralPath $state.Report)){$match=[regex]::Match((Get-Content -LiteralPath $state.Report -Raw),'(?:Create|Attach)Process=1 error=\d+ pid=(\d+)');if($match.Success){$ownPid=[int]$match.Groups[1].Value}}
$testProcesses=@(Get-CimInstance Win32_Process -Filter "Name = 'StartMenuExperienceHost.exe'" | Where-Object {$_.ExecutablePath -ieq $state.TestPath -and $_.CreationDate.ToUniversalTime() -ge $startTime.AddSeconds(-2) -and (-not $state.NativePathMode -or ($ownPid -ne 0 -and $_.ProcessId -eq $ownPid))})
foreach($test in $testProcesses){Stop-Process -Id $test.ProcessId -Force -ErrorAction SilentlyContinue}
$native=@(Get-CimInstance Win32_Process -Filter "Name = 'StartMenuExperienceHost.exe'" | Where-Object {$_.ExecutablePath -ieq $state.NativePath})
if(-not $native){
 $activationTool=Join-Path $PSScriptRoot 'PackageDebugController.exe'
 if(Test-Path -LiteralPath $activationTool){
  $activation=Start-NonUiProcess -FilePath $activationTool -ArgumentList @('activate',($state.PackageFamily+'!App')) -RedirectStandardOutput ($StatePath+'.restore-activation.log') -RedirectStandardError ($StatePath+'.restore-activation.err')
 }else{Invoke-CommandInDesktopPackage -PackageFamilyName $state.PackageFamily -AppId App -Command $state.NativePath -Args $state.ServerArgument -PreventBreakaway}
}
$deadline=[DateTime]::UtcNow.AddSeconds(10)
do {
 $native=@(Get-CimInstance Win32_Process -Filter "Name = 'StartMenuExperienceHost.exe'" | Where-Object {$_.ExecutablePath -ieq $state.NativePath})
 if($native){break}
 Start-Sleep -Milliseconds 200
} while([DateTime]::UtcNow -lt $deadline)
[pscustomobject]@{RestoreUtc=[DateTime]::UtcNow.ToString('o');NativePresent=[bool]$native;NativePids=@($native | ForEach-Object {[int]$_.ProcessId});TerminatedTestPids=@($testProcesses | ForEach-Object {[int]$_.ProcessId})} | ConvertTo-Json | Set-Content -LiteralPath ($StatePath+'.restored.json') -Encoding UTF8
} finally {if($owned){$mutex.ReleaseMutex()};$mutex.Dispose()}
