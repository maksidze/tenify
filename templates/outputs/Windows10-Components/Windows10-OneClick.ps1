param([ValidateSet('Start','Restore','Check')][string]$Mode='Start',[string]$ComponentRoot=$PSScriptRoot)
$ErrorActionPreference='Stop'
$ComponentRoot=[IO.Path]::GetFullPath($ComponentRoot)
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
$required=@('Start-Windows10-Persistent.ps1','Stop-Windows10-Persistent.ps1','Stop-Windows10-Maximum.ps1','Launch-NonUiProcess.ps1','NonUiProcess.cs','Runtime\Explorer10\explorer.exe','Lab\StartSessionCompat\Enable-Start10-Session.ps1','Lab\StartSessionCompat\Start10SessionDebugger.exe','Lab\StartCompat\StartUI_.dll','Lab\DisplayMonitorPublisher\Ensure-MonitorPublisherUntilStop.ps1','Lab\DisplayMonitorPublisher\MonitorPublisherUntilStop.exe','Lab\SettingsUntilStopCompat\SessionController.py','Lab\SettingsUntilStopCompat\SessionVFS.py','Lab\SettingsUntilStopCompat\private-usvfs-provenance.json','Lab\SettingsUntilStopCompat\Settings10UntilStopDebugger.exe','Lab\SettingsCaptionCompat\SettingsCaptionCompat.dll','Lab\SettingsContentCompat\SettingsContentCompat.dll','Lab\NetworkTrayUntilStopCompat\Ensure-NetworkTrayUntilStop.ps1','Lab\NetworkTrayUntilStopCompat\NetworkTrayUntilStop.exe','Lab\WindowStyleSession\WindowCorners.ps1','Lab\ElevatedCornersCompat\ElevatedCorners.ps1','Lab\ElevatedCornersCompat\ElevatedCornerHost.exe','WindowStyle\SnapHover.ps1','Tools\USVFS\bin\usvfs_x64.dll','Tools\USVFS\bin\usvfs_proxy_x64.exe','Image\4\Windows\ImmersiveControlPanel\resources.pri')
$mutex=New-Object Threading.Mutex($false,'Local\Windows10OneClickBundle')
$held=$false;$transcript=$false;$run=$null;$failed=$false
$report=[ordered]@{Version='oneclick-11';Mode=$Mode;StartedUtc=[DateTime]::UtcNow.ToString('o');Status='starting';Lifetime='UntilStop';Stages=@();MaximumState=$null;SystemFilesModified=$false}
function Save-Report {if($run){$report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $run 'status.json') -Encoding UTF8}}
function Run-Stage([string]$name,[scriptblock]$action){
 Write-Host ('--- '+$name)
 $stage=[ordered]@{Name=$name;Status='running';Error=$null}
 try{& $action|Out-Host;$stage.Status='completed'}catch{$stage.Status='failed';$stage.Error=$_.Exception.Message;$script:failed=$true;Write-Warning ($name+': '+$stage.Error)}
 $script:report.Stages+=@($stage);Save-Report
}
try{
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){throw 'Another bundle start/restore is in progress. Wait for its result.'}
 $run=Join-Path $ComponentRoot ('state-oneclick\'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N'))
 [IO.Directory]::CreateDirectory($run)|Out-Null
 Start-Transcript -LiteralPath (Join-Path $run 'run.log')|Out-Null;$transcript=$true
 Save-Report
 if($Mode -ne 'Restore'){
  foreach($relative in $required){if(!(Test-Path -LiteralPath (Join-Path $ComponentRoot $relative) -PathType Leaf)){throw ('Missing component: '+$relative)}}
  $python='@PYTHON_DIR@\python.exe'
  if(!(Test-Path -LiteralPath $python)){throw 'The required Python runtime is missing.'}
  # Validate the actual Settings bootstrap chain without activation or registration.
  foreach($relative in @('Lab\SettingsUntilStopCompat\manifest.json','Lab\StartSessionCompat\manifest.json','Lab\NetworkTrayUntilStopCompat\manifest.json','Lab\DisplayMonitorPublisher\untilstop-manifest.json','Lab\ElevatedCornersCompat\manifest.json','Lab\HybridThemeBootstrap\manifest.json','Lab\ThemeMenuBootstrap\manifest.json')){
   $manifest=Get-Content -LiteralPath (Join-Path $ComponentRoot $relative) -Raw -Encoding UTF8|ConvertFrom-Json
   foreach($item in $manifest.Files){if((Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash -ine $item.SHA256){throw ('Dependency changed: '+$item.Path)}}
  }
  & $python (Join-Path $ComponentRoot 'Validate-ShellExtensions.py')
  if($LASTEXITCODE -ne 0){throw 'Classic menu or Icons10Maximum dependency validation failed.'}
 }
 if($Mode -eq 'Check'){
  $report.Status='dependencies-verified';Write-Host 'Dependency checks passed. No shell, application or setting was changed.'
 }elseif($Mode -eq 'Start'){
  $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if($admin){throw 'Run this BAT normally, not as administrator. Elevation is requested separately for the recovery guard and elevated-window corner companion.'}
  Write-Host 'Starting the current Windows 10 interface bundle. Explorer may restart; a UAC prompt may appear.'
  Write-Host 'Components run until explicit Stop, sign-out or owner shutdown. Bootstrap watchdogs remain finite.'
  $maximumRoot=Join-Path $ComponentRoot 'state-persistent'
  $before=@(if(Test-Path -LiteralPath $maximumRoot){Get-ChildItem -LiteralPath $maximumRoot -Directory|ForEach-Object Name})
  Run-Stage 'Explorer 10, Start 10, Settings 10, Task View and network UntilStop' {& (Join-Path $ComponentRoot 'Start-Windows10-Persistent.ps1')}
  $created=@(Get-ChildItem -LiteralPath $maximumRoot -Directory -ErrorAction SilentlyContinue|Where-Object {$_.Name -notin $before -and $_.Name -match '^[0-9a-f]{32}$'})
  if($created.Count -eq 1 -and (Test-Path -LiteralPath (Join-Path $created[0].FullName 'status.json'))){
   $report.MaximumState=Join-Path $created[0].FullName 'status.json'
   $maximum=Get-Content -LiteralPath $report.MaximumState -Raw -Encoding UTF8|ConvertFrom-Json
   if($maximum.Status -ne 'running' -or !$maximum.SettingsIncluded){$failed=$true;Write-Warning 'Some persistent components were not enabled; inspect component status.json.'}
  }else{$failed=$true;Write-Warning 'A unique persistent readiness report was not found.'}
  Run-Stage 'Square window corners' {& (Join-Path $ComponentRoot 'Lab\WindowStyleSession\WindowCorners.ps1') -Mode Enable -UntilStop}
  Run-Stage 'Square corners of elevated application windows' {& (Join-Path $ComponentRoot 'Lab\ElevatedCornersCompat\ElevatedCorners.ps1') -Mode Enable}
  Run-Stage 'Disable Snap Layout hover and refresh shell cache' {& (Join-Path $ComponentRoot 'WindowStyle\SnapHover.ps1') -Action Disable}
  $report.Status=if($failed){'partial-or-failed'}else{'started'}
 }else{
  # A failure restoring one component must not prevent the other restore attempts.
  Run-Stage 'Stop owned network tray handler' {& (Join-Path $ComponentRoot 'Lab\NetworkTrayCompat\Stop-NetworkTray.ps1')}
  Run-Stage 'Restore elevated application window corners' {& (Join-Path $ComponentRoot 'Lab\ElevatedCornersCompat\ElevatedCorners.ps1') -Mode Disable}
  Run-Stage 'Restore original window corners' {& (Join-Path $ComponentRoot 'Lab\WindowStyleSession\WindowCorners.ps1') -Mode Disable}
  Run-Stage 'Restore Snap hover preference' {& (Join-Path $ComponentRoot 'WindowStyle\SnapHover.ps1') -Action Restore}
  Run-Stage 'Stop owned Settings/Start/Explorer sessions and restore native Explorer' {& (Join-Path $ComponentRoot 'Stop-Windows10-Maximum.ps1')}
  $report.Status=if($failed){'restore-partial-or-failed'}else{'restored'}
 }
 Save-Report
 Write-Host ('Result: '+$report.Status)
 Write-Host ('Logs: '+$run)
}catch{
 $failed=$true;$report.Status='failed';$report.Error=$_.Exception.Message;Save-Report
 Write-Host ('ERROR: '+$_.Exception.Message) -ForegroundColor Red
 if($run){Write-Host ('Logs: '+$run)}
}finally{
 if($transcript){Stop-Transcript|Out-Null}
 if($held){$mutex.ReleaseMutex()};$mutex.Dispose()
}
if($failed){exit 1}
exit 0
