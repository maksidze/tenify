param([ValidateSet('Start','Restore','Check')][string]$Mode='Start')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lab/DirectLaunchLifecycle/Lifecycle.ps1')
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
foreach($name in 'Utility','Management','Security'){Import-Module (Join-Path $PSHOME ('Modules/Microsoft.PowerShell.'+$name+'/Microsoft.PowerShell.'+$name+'.psd1')) -ErrorAction Stop}
$run=Join-Path $PSScriptRoot ('state-oneclick-direct/'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($run)|Out-Null
$report=[ordered]@{Version='direct-12';Mode=$Mode;NoVFS=$true;Status='starting';SystemFilesModified=$false;Stages=@();Logs=$run}
$failed=$false;$held=$false;$transcript=$false;$restoreGates=$null
$mutex=New-Object Threading.Mutex($false,'Local\Windows10OneClickBundle')
function Save-Report {$report|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $run 'status.json') -Encoding UTF8}
function Stage([string]$name,[scriptblock]$action){
 $item=[ordered]@{Name=$name;Status='running'}
 try{& $action|Out-Host;$item.Status='ready'}catch{$item.Status='failed';$item.Error=$_.Exception.Message;$script:failed=$true;Write-Warning $item.Error}
 $script:report.Stages+=@($item);Save-Report
}
try{
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){throw 'Another interface start or restore is active.'}
 Start-Transcript -LiteralPath (Join-Path $run 'run.log')|Out-Null;$transcript=$true
 if($Mode -ne 'Restore'){
  foreach($file in 'Start-Explorer10-Direct.ps1','Start-Windows10-DirectPersistent.ps1','Lab/SettingsNoVfsSessionCompat/Enable-Settings10-NoVFS.ps1','Lab/NoVfsShellCompat/manifest.json','Lab/SettingsNoVfsSessionCompat/manifest.json','Lab/SettingsNoVfsXamlCompat/manifest.json'){
   if(!(Test-Path -LiteralPath (Join-Path $PSScriptRoot $file) -PathType Leaf)){throw ('Missing direct component: '+$file)}
  }
  foreach($file in 'Lab/NoVfsShellCompat/manifest.json','Lab/SettingsNoVfsSessionCompat/manifest.json','Lab/SettingsNoVfsXamlCompat/manifest.json'){
   $manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot $file) -Raw -Encoding UTF8|ConvertFrom-Json
   if(!$manifest.NoVFS){throw 'Component is not a direct loader.'}
   foreach($row in $manifest.Files){if((Get-FileHash -LiteralPath $row.Path).Hash -ine $row.SHA256){throw ('Changed dependency: '+$row.Path)}}
  }
 }
 if($Mode -eq 'Check'){$report.Status='dependencies-verified'}
 elseif($Mode -eq 'Start'){
  if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run normally. Recovery guards request elevation separately.'}
  Stage 'Windows 10 Explorer pin and target folder cache' {& (Join-Path $PSScriptRoot 'Lab/TargetIconRepair/Setup-TargetIcons.ps1')}
  Stage 'Direct shell, Start, Settings, Task View and tray' {& (Join-Path $PSScriptRoot 'Start-Windows10-DirectPersistent.ps1')}
  Stage 'Square window corners' {& (Join-Path $PSScriptRoot 'Lab/WindowStyleSession/WindowCorners.ps1') -Mode Enable -UntilStop}
  Stage 'Square elevated window corners' {& (Join-Path $PSScriptRoot 'Lab/ElevatedCornersCompat/ElevatedCorners.ps1') -Mode Enable}
  Stage 'Disable snap hover' {& (Join-Path $PSScriptRoot 'WindowStyle/SnapHover.ps1') -Action Disable}
  $report.Status=if($failed){'partial-or-failed'}else{'started'}
 }else{
  $restoreGates=Enter-DirectRestoreGates
  Stage 'Restore owned Explorer pin' {& (Join-Path $PSScriptRoot 'Lab/TargetIconRepair/Restore-TargetIcons.ps1')}
  Stage 'Stop direct Settings' {& (Join-Path $PSScriptRoot 'Lab/SettingsNoVfsSessionCompat/Disable-Settings10-NoVFS.ps1')}
  Stage 'Stop Start and tray companions' {& (Join-Path $PSScriptRoot 'Stop-Windows10-DirectPersistent.ps1')}
  Stage 'Stop direct Explorer' {& (Join-Path $PSScriptRoot 'Stop-Explorer10-Direct.ps1')}
  Stage 'Wait for native shell recovery' {& (Join-Path $PSScriptRoot 'Confirm-NativeExplorer.ps1')}
  Stage 'Restore elevated window corners' {& (Join-Path $PSScriptRoot 'Lab/ElevatedCornersCompat/ElevatedCorners.ps1') -Mode Disable}
  Stage 'Restore window corners' {& (Join-Path $PSScriptRoot 'Lab/WindowStyleSession/WindowCorners.ps1') -Mode Disable}
  Stage 'Restore snap hover' {& (Join-Path $PSScriptRoot 'WindowStyle/SnapHover.ps1') -Action Restore}
  $report.Status=if($failed){'restore-partial-or-failed'}else{'restored'}
 }
}catch{$failed=$true;$report.Status='failed';$report.Error=$_.Exception.Message;Write-Warning $report.Error}
finally{Save-Report;Write-Host ('Result: '+$report.Status+'; logs: '+$run);if($transcript){Stop-Transcript|Out-Null};if($restoreGates){Exit-DirectRestoreGates $restoreGates};if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
if($failed){exit 1}
