param([ValidateRange(15,300)][int]$Seconds=300)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
$lab=Join-Path $PSScriptRoot 'Lab\SettingsBrokerCompat'
$python='@PYTHON_DIR@\python.exe'
$mutex=New-Object Threading.Mutex($false,'Local\Settings10ManualLauncher')
$mutexHeld=$false
try{
 try{$mutexHeld=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$mutexHeld=$true}
 if(!$mutexHeld){throw 'Another manual Settings launcher is active.'}
 $package=Get-AppxPackage windows.immersivecontrolpanel
 if(!$package){throw 'Native Settings package missing.'}
 $debugA='HKCU:\Software\Classes\ActivatableClasses\Package\'+$package.PackageFullName+'\DebugInformation'
 $debugB='HKCU:\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\'+$package.PackageFullName
 if((Test-Path -LiteralPath $debugA) -or (Test-Path -LiteralPath $debugB)){throw 'Existing Settings debugger session; no configuration overwritten.'}
 if(Get-Process SystemSettings -ErrorAction SilentlyContinue){throw 'Settings is already running; close it before this test.'}
 foreach($stateFile in Get-ChildItem -LiteralPath (Join-Path $lab 'state') -Filter 'settings-*.json'){
  if($stateFile.Name -like '*.restored.json'){continue}
  $state=Get-Content -LiteralPath $stateFile.FullName -Raw | ConvertFrom-Json
  if(!(Test-Path -LiteralPath ($stateFile.FullName+'.restored.json')) -and [DateTime]::Parse($state.DeadlineUtc).ToUniversalTime() -gt [DateTime]::UtcNow){throw 'A Settings guard/session is active; wait for restore.'}
 }
$preparedPath=& (Join-Path $lab 'Prepare-SettingsBroker.ps1') -VfsInstance ('settingsmanual'+[guid]::NewGuid().ToString('N')) -Seconds $Seconds
$prepared=Get-Content -LiteralPath $preparedPath -Raw | ConvertFrom-Json
$oldBootstrap=$prepared.Bootstrap
$prepared.Bootstrap=Join-Path $PSScriptRoot 'Lab\SettingsSystemProfileCompat\SettingsSystemProfileCompat.dll'
$detachedDebugger=Join-Path $lab 'SettingsBrokerDetached.exe'
$immutableConfig=$prepared.Report+'.ini'
if($detachedDebugger.Contains(' ') -or $immutableConfig.Contains(' ')){throw 'Debugger command requires the verified workspace without spaces.'}
$prepared | Add-Member -NotePropertyName Config -NotePropertyValue $immutableConfig -Force
$prepared.Debugger=$detachedDebugger+' --config '+[IO.Path]::GetFileName($immutableConfig)
if($prepared.Debugger.Length -ge 260){throw 'Debugger command exceeds the verified EnableDebugging limit (259 characters).'}
# Supervisor reserves recovery time; debugger child runtime remains the requested Seconds.
$prepared.RequiredLifetimeSeconds=$Seconds
$prepared | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $preparedPath -Encoding UTF8
$config=Join-Path $lab 'BrokerSettingsCompat.ini'
$text=[IO.File]::ReadAllText($config,[Text.Encoding]::Unicode).Replace(('Proxy='+$oldBootstrap),('Proxy='+$prepared.Bootstrap))
$text += 'CancelFile='+$preparedPath+'.cancel'+"`r`n"
[IO.File]::WriteAllText($immutableConfig,$text,[Text.Encoding]::Unicode)
[IO.File]::WriteAllText((Join-Path $lab 'manual-current-prepared.txt'),$preparedPath)
Write-Host ('Settings 10 requested for '+$Seconds+' seconds. Bootstrap detaches before Application.Start. Content/functionality remain under review.')
Write-Host ('Log: '+$prepared.Report)
. (Join-Path $PSScriptRoot 'Launch-NonUiProcess.ps1')
$ownedController=Start-NonUiProcess -FilePath $python -ArgumentList @((Join-Path $lab 'SettingsVfsController.py'),'--prepared-state',$preparedPath,'--execute') -RedirectStandardOutput ($prepared.Report+'.supervisor.log') -RedirectStandardError ($prepared.Report+'.supervisor.err')
try {while(!$ownedController.WaitForExit(1000)){};if($ownedController.ExitCode){throw ('Controller exit '+$ownedController.ExitCode)}} finally {$ownedController.Dispose()}

}finally{if($mutexHeld){$mutex.ReleaseMutex()};$mutex.Dispose()}
