param([Parameter(Mandatory=$true)][string]$Config)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$cfg=Read-Json $Config
if(!$cfg -or $cfg.Format -ne 1 -or [IO.Path]::GetFullPath($Config) -ine [IO.Path]::GetFullPath((Join-Path $data ($cfg.Session+'.config.json')))){throw 'Invalid private session configuration.'}
$status=Join-Path $data ($cfg.Session+'.status.json')
$self=Get-Process -Id $PID
$record=[ordered]@{Pid=$PID;BirthFileTime=[string]$self.StartTime.ToUniversalTime().ToFileTimeUtc();Path=$self.Path;Session=$cfg.Session;Config=$Config;Cancel=$cfg.Cancel;Status='starting';Journal=$journal;StartedUtc=[DateTime]::UtcNow.ToString('o')}
$mutex=New-JournalMutex;$held=$false
try {
 $held=Lock-Mutex $mutex
 if(!$held){throw 'Shared journal is already owned by a controller.'}
 # Always restore a previous crashed session before starting a new one.
 Restore-Windows
 if(@(Read-Journal).Count){throw 'Previous baseline restoration remains incomplete.'}
 if($cfg.Scope -eq 'Fixture'){
  if(!$cfg.TargetPid -or !$cfg.TargetBirth -or !$cfg.TargetPath -or $cfg.TargetPath -ine (Join-Path $PSScriptRoot 'CornerFixture.exe')){throw 'Invalid own fixture scope.'}
  $originalCandidates=(Get-Command Get-Candidates).ScriptBlock
  Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.Runtime.InteropServices;
public static class CornerFixtureWindows {
 delegate bool E(IntPtr h,IntPtr p);[DllImport("user32.dll")]static extern bool EnumWindows(E e,IntPtr p);
 public static long[] All(){var a=new List<long>();EnumWindows((h,p)=>{a.Add(h.ToInt64());return true;},IntPtr.Zero);return a.ToArray();}
}
'@
  function Get-Candidates {
   $target=Get-Process -Id ([int]$cfg.TargetPid) -ErrorAction Stop
   if($target.Path -ine $cfg.TargetPath -or [string]$target.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [string]$cfg.TargetBirth){throw 'Own fixture process identity changed.'}
   foreach($handle in [CornerFixtureWindows]::All()){$id=Get-Identity $handle;if($id -and $id.Pid -eq $cfg.TargetPid -and $id.Class -eq 'CodexCornerFixture'){$id}}
  }
 }elseif($cfg.Scope -ne 'AllVisible'){throw 'Unknown session scope.'}
 $record.Status='running';Write-AtomicJson $status $record
 while(!(Test-Path -LiteralPath $cfg.Cancel) -and ($cfg.UntilStop -or [DateTime]::UtcNow -lt [DateTime]::Parse($cfg.DeadlineUtc).ToUniversalTime())){
  Set-Square
  Start-Sleep -Milliseconds 350
 }
}catch{$record.Status='failed';$record.Error=$_.Exception.Message;throw}
finally{
 try {if($held){Restore-Windows;$record.RemainingBaselines=@(Read-Journal).Count;$record.Status=if($record.RemainingBaselines){'restore-incomplete'}elseif($record.Error){'failed-restored'}else{'stopped'};Write-AtomicJson $status $record}}
 finally {if($held){$mutex.ReleaseMutex()};$mutex.Dispose();$self.Dispose()}
}
