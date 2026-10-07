param([ValidateSet('Status','Disable','Restore')][string]$Action='Status')
$ErrorActionPreference='Stop'
$subkey='Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$valueName='EnableSnapAssistFlyout'
$statePath=Join-Path $PSScriptRoot 'SnapHover-state.json'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$mutex=New-Object Threading.Mutex($false,'Local\Windows10SnapHoverPreference')
$held=$false
function Save-State($state){
 $temp=$statePath+'.tmp'
 $state|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $temp -Encoding UTF8
 Move-Item -LiteralPath $temp -Destination $statePath -Force
}
function Read-Value{
 $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($subkey)
 try{
  if($key -and $key.GetValueNames() -contains $valueName){
   $kind=$key.GetValueKind($valueName).ToString()
   if($kind -ne 'DWord'){throw 'Unexpected registry value type; no change made.'}
   return [pscustomobject]@{Exists=$true;Kind=$kind;Value=[int]$key.GetValue($valueName)}
  }
  return [pscustomobject]@{Exists=$false;Kind=$null;Value=$null}
 }finally{if($key){$key.Dispose()}}
}
function Read-FileSha([string]$path){
 $algorithm=[Security.Cryptography.SHA256]::Create();$file=$null
 try{$file=[IO.File]::OpenRead($path);return [BitConverter]::ToString($algorithm.ComputeHash($file)).Replace('-','').ToLowerInvariant()}
 finally{if($file){$file.Dispose()};$algorithm.Dispose()}
}
function Assert-CacheTools{
 $componentRoot=Split-Path -Parent $PSScriptRoot
 $pins=@{
  'Lab\SnapHoverCompat\SnapCacheNotify.exe'='f16269176b5ea6fc1de22bfacd357c413eb1956882de6ea5679f2c173de9c83e'
  'Lab\SnapHoverCompat\SnapCacheNotify.cs'='a963ebb96e9c563f9dcf7c14a9b1f0d1779324b9386a6842083074c971947e30'
  'Launch-NonUiProcess.ps1'='06ce589e3018ce3dc7d62a869b1a15900eea4d0f635bee1a97d1939b8cae0c1e'
  'NonUiProcess.cs'='a3f022a17edf21956cba45ebe5059755a113cb1eedaa1523cecbe69bd5bad287'
 }
 foreach($relative in $pins.Keys){
  if((Read-FileSha (Join-Path $componentRoot $relative)) -cne $pins[$relative]){throw "Snap cache tool hash mismatch: $relative"}
 }
 if((Read-FileSha (Join-Path $env:WINDIR 'System32\twinui.dll')) -cne '10ae13c8560cc89abb33425f9b9e6d49368d43f39e73e3845f3f0e191eb5af2f'){throw 'Unsupported twinui.dll version; preference was not changed.'}
}
function Notify-Preference{
 Assert-CacheTools
 $componentRoot=Split-Path -Parent $PSScriptRoot
 . (Join-Path $componentRoot 'Launch-NonUiProcess.ps1')
 $logs=Join-Path $PSScriptRoot 'SnapHover-logs'
 [void][IO.Directory]::CreateDirectory($logs)
 $prefix=Join-Path $logs ([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N'))
 $child=$null;$done=$false
 try{
  $child=Start-NonUiProcess -FilePath (Join-Path $componentRoot 'Lab\SnapHoverCompat\SnapCacheNotify.exe') -ArgumentList @('--refresh') -RedirectStandardOutput ($prefix+'.jsonl') -RedirectStandardError ($prefix+'.stderr')
  $done=$child.WaitForExit(15000)
  if(!$done){throw 'COM refresh timed out; the shell has not been restarted.'}
  if($child.ExitCode -ne 0){throw ('Cache helper returned '+$child.ExitCode+'.')}
  $events=@(Get-Content -LiteralPath ($prefix+'.jsonl')|ForEach-Object{$_|ConvertFrom-Json})
  if(!($events|Where-Object{$_.result -eq 'refreshed' -and $_.matchesFresh -eq $true})){throw 'Cache helper did not confirm a matching genuine fresh cache value.'}
  Write-Output ('Live shell cache refreshed (setting 11). Log: '+$prefix+'.jsonl')
 }catch{
  throw ('The registry preference and backup are preserved, but live cache refresh was not confirmed. No Explorer restart was attempted. '+$_.Exception.Message+' Log: '+$prefix+'.jsonl')
 }finally{
  if($child){try{if(!$done){$child.Kill();[void]$child.WaitForExit(3000)}}finally{$child.Dispose()}}
 }
}
try{
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){throw 'Another Snap preference operation is running.'}
 $current=Read-Value
 $saved=$null
 if(Test-Path -LiteralPath $statePath){
  $saved=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
  if($saved.Format -ne 1 -or $saved.Sid -ne $sid -or $saved.Subkey -cne $subkey -or $saved.Name -cne $valueName){throw 'Backup identity mismatch.'}
 }
 switch($Action){
 Status{[pscustomobject]@{ValueExists=$current.Exists;Value=$current.Value;DefaultWhenAbsent=1;BackupStatus=if($saved){$saved.Status}else{'none'}}|ConvertTo-Json}
 Disable{
  if($saved -and $saved.Status -in @('captured','applied')){
   if($current.Exists -and $current.Value -eq 0){Notify-Preference;Write-Output 'Hover Snap layout preference is already disabled; original backup kept.';break}
   throw 'Preference changed since the previous session. Restore first to preserve that change.'
  }
  Assert-CacheTools
  $saved=[ordered]@{Format=1;Sid=$sid;Subkey=$subkey;Name=$valueName;Original=$current;Status='captured';CapturedUtc=[DateTime]::UtcNow.ToString('o')}
  Save-State $saved
  $key=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($subkey)
  try{$key.SetValue($valueName,0,[Microsoft.Win32.RegistryValueKind]::DWord);$key.Flush()}finally{$key.Dispose()}
  $readback=Read-Value
  if(!$readback.Exists -or $readback.Value -ne 0){throw 'Preference readback failed; backup retained.'}
  $saved.Status='applied';Save-State $saved
  Notify-Preference
  Write-Output 'Hover Snap layouts disabled. Original preference saved; visual result needs confirmation.'
 }
 Restore{
  if(!$saved -or $saved.Status -notin @('captured','applied')){
   if($saved -and $saved.Status -in @('restored','changed-externally-preserved')){Notify-Preference}
   Write-Output 'No active Snap preference backup.';break
  }
  if(!$current.Exists -or $current.Value -ne 0){
   $saved.Status='changed-externally-preserved';Save-State $saved
   Notify-Preference
   Write-Output 'Preference was changed externally; its current value was preserved.';break
  }
  Assert-CacheTools
  $key=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($subkey)
  try{
   if($saved.Original.Exists){
    if($saved.Original.Kind -ne 'DWord'){throw 'Invalid original value type.'}
    $key.SetValue($valueName,[int]$saved.Original.Value,[Microsoft.Win32.RegistryValueKind]::DWord)
   }else{$key.DeleteValue($valueName,$false)}
   $key.Flush()
  }finally{$key.Dispose()}
  $readback=Read-Value
  if($readback.Exists -ne $saved.Original.Exists -or ($readback.Exists -and $readback.Value -ne $saved.Original.Value)){throw 'Restore readback failed; backup retained.'}
  $saved.Status='restored';Save-State $saved
  Notify-Preference
  Write-Output 'Original hover Snap layout preference restored.'
 }
 }
}finally{if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
