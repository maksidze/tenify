param([ValidateRange(5,3600)][int]$Seconds=180,[string]$ActivationArguments='Windows.Internal.ShellExperience.StartMenu',[switch]$DetachAfterBootstrap,[switch]$DiagnosticOrdinaryTimeouts)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\..\Launch-NonUiProcess.ps1')
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
$package=Get-AppxPackage -Name Microsoft.Windows.StartMenuExperienceHost
if(-not $package){throw 'Native Start package is not registered.'}
$nativePath=Join-Path $package.InstallLocation 'StartMenuExperienceHost.exe'
$native=@(Get-CimInstance Win32_Process -Filter "Name = 'StartMenuExperienceHost.exe'" | Where-Object {$_.ExecutablePath -ieq $nativePath})
if($native){$server=[regex]::Match($native[0].CommandLine,'-ServerName:\S+').Value}else{
 $previous=Get-ChildItem (Join-Path $PSScriptRoot 'state') -Filter 'broker-*.json' | Where-Object {$_.Name -match '^broker-[a-f0-9]+\.json$'} | Sort-Object LastWriteTime -Descending | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json} | Where-Object {$_.PackageFullName -eq $package.PackageFullName -and $_.ServerArgument} | Select-Object -First 1
 $server=$previous.ServerArgument
}
if(-not $server){throw 'No observed native server argument.'}
$id=[Guid]::NewGuid().ToString('N').Substring(0,12)
$statePath=Join-Path $PSScriptRoot "state\broker-$id.json"
$report=Join-Path $PSScriptRoot "broker-host-$id.log"
$registryPaths=@(
 ('HKCU:\Software\Classes\ActivatableClasses\Package\'+$package.PackageFullName+'\DebugInformation'),
 ('HKCU:\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\'+$package.PackageFullName),
 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe'
)
function Read-DebugSnapshot {
 $rows=@()
 foreach($path in $registryPaths){
  $exists=Test-Path -LiteralPath $path
  $keys=@();if($exists){$keys=@(Get-Item -LiteralPath $path)+@(Get-ChildItem -LiteralPath $path -Recurse)}
  $values=@();foreach($key in $keys){foreach($name in $key.GetValueNames()){$values += [pscustomobject]@{Key=$key.Name;Name=$name;Kind=$key.GetValueKind($name).ToString();Value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}}}
  $rows += [pscustomobject]@{Path=$path;Exists=$exists;Values=$values}
 }
 return $rows
}
$before=@(Read-DebugSnapshot)
$before | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath ($statePath+'.debug-before.json') -Encoding UTF8
if(@($before | Where-Object {$_.Exists}).Count){throw 'A pre-existing debug/IFEO key was found. Its exact snapshot is preserved; nothing will be overwritten.'}
$start=[DateTime]::UtcNow
[pscustomobject]@{StartUtc=$start.ToString('o');DeadlineUtc=$start.AddSeconds($Seconds+30).ToString('o');TestPath=$nativePath;NativePath=$nativePath;NativePathMode=$true;PackageDebugMode=$true;PackageFullName=$package.PackageFullName;NativeBaselines=@($native | ForEach-Object {[pscustomobject]@{Pid=[int]$_.ProcessId;CreationUtc=$_.CreationDate.ToUniversalTime().ToString('o')}});PackageFamily=$package.PackageFamilyName;ServerArgument=$server;Report=$report} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8
$powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$restore=Join-Path $PSScriptRoot 'Restore-StartCompat.ps1'
$guard=Start-NonUiProcess -FilePath $powershell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$restore,'-StatePath',$statePath,'-Guard') -RedirectStandardOutput ($statePath+'.guard.log') -RedirectStandardError ($statePath+'.guard.err')
$controller=Join-Path $PSScriptRoot 'PackageDebugController.exe'
$probe=Join-Path $PSScriptRoot 'StartCompatHostProbe.exe'
$proxy=Join-Path $PSScriptRoot 'wincorlib.dll'
$runtimeIni=Join-Path $PSScriptRoot 'StartCompat.ini'
$runtimeText=[regex]::Replace([IO.File]::ReadAllText($runtimeIni),'(?m)^DiagnosticOrdinaryTimeouts=[^\r\n]*(?:\r?\n|$)','')
$runtimeText=$runtimeText.Replace('[Options]',"[Options]`r`nDiagnosticOrdinaryTimeouts=$([int][bool]$DiagnosticOrdinaryTimeouts)")
[IO.File]::WriteAllText($runtimeIni,$runtimeText,[Text.Encoding]::Unicode)

$config="[Debugger]`r`nReport=$report`r`nTarget=$nativePath`r`nSeconds=$Seconds`r`nDetachAfterBootstrap=$([int][bool]$DetachAfterBootstrap)`r`nServerArgument=$server`r`nProxy=$proxy`r`nPackageFullName=$($package.PackageFullName)`r`nDeadlineFileTime=$($start.AddSeconds($Seconds+20).ToFileTimeUtc())`r`n"
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'BrokerStartCompat.ini'),$config,[Text.Encoding]::Unicode)
$debugger=$probe
# The helper quotes each literal argument exactly once.
$arguments=@('enable',$package.PackageFullName,$debugger,[string]($Seconds+20),($statePath+'.restore'))
try {
 $control=Start-NonUiProcess -FilePath $controller -ArgumentList $arguments -RedirectStandardOutput ($statePath+'.enable.log') -RedirectStandardError ($statePath+'.enable.err')
 $deadline=[DateTime]::UtcNow.AddSeconds(10)
 while([DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath ($statePath+'.restore.enabled'))){Start-Sleep -Milliseconds 100}
 if(-not (Test-Path -LiteralPath ($statePath+'.restore.enabled'))){throw 'EnableDebugging did not signal success.'}
 Read-DebugSnapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath ($statePath+'.debug-enabled.json') -Encoding UTF8
 foreach($baseline in $native){
  $check=Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $baseline.ProcessId)
  if(-not $check){continue}
  if($check.ExecutablePath -ine $nativePath -or $check.CreationDate -ne $baseline.CreationDate){throw 'Native Start changed before controlled activation.'}
  Stop-Process -Id $baseline.ProcessId -Force
 }
 $activation=Start-NonUiProcess -FilePath $controller -ArgumentList @('activate',($package.PackageFamilyName+'!App'),$ActivationArguments) -RedirectStandardOutput ($statePath+'.activation.log') -RedirectStandardError ($statePath+'.activation.err')
 $deadline=[DateTime]::UtcNow.AddSeconds($Seconds+5)
 while([DateTime]::UtcNow -lt $deadline){if(Test-Path -LiteralPath ($statePath+'.restore')){break};if((Test-Path -LiteralPath $report) -and ((Get-Content -LiteralPath $report -Raw) -match 'COMPLETE|EXIT code=')){break};Start-Sleep -Milliseconds 200}
} finally {
 [IO.File]::WriteAllText($statePath+'.restore','Restore requested by broker test supervisor')
 & $restore -StatePath $statePath
 Read-DebugSnapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath ($statePath+'.debug-after.json') -Encoding UTF8
}
Write-Output "State=$statePath"
Write-Output "Report=$report"
Get-Content -LiteralPath ($statePath+'.restored.json')
