param([Parameter(Mandatory=$true)][string]$Config,[switch]$OwnFixture,[switch]$RecoverOnly)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$cfg=Validate-Config $Config
$me=[CornerAccess]::Read([uint32]$PID)
try{if(!$me){throw 'Controller identity unavailable.'};if(!$OwnFixture -and ($me.Integrity -lt 12288 -or $me.Integrity -ge 16384)){throw 'Production controller requires user High integrity.'};if([bool]$OwnFixture -ne ($cfg.Scope -eq 'Fixture')){throw 'Fixture/production scope mismatch.'}}finally{if($me){$me.Dispose()}}
if($cfg.Scope -notin @('AllHigh','Fixture')){throw 'Unsupported scope.'}
. (Join-Path $PSScriptRoot 'Library.ps1') -Action Library -StatePath $cfg.Journal
$mutexName=if($OwnFixture){'Local\CodexElevatedCornersFixture_'+$cfg.Session}else{'Local\CodexElevatedCornersJournalV1'}
$mutex=New-Object Threading.Mutex($false,$mutexName)
$held=$false;$status=@{Session=$cfg.Session;Pid=$PID;Status='starting';Journal=$cfg.Journal;Scope=$cfg.Scope}
function Save-Journal($entries){Write-Json $cfg.Journal @($entries)}
$baseCandidates=(Get-Command Get-Candidates).ScriptBlock
if($OwnFixture){
 if($cfg.TargetPath -ine (Join-Path $PSScriptRoot 'ElevatedCornerFixture.exe') -or !$cfg.TargetBirth -or !$cfg.TargetPid){throw 'Own fixture exact identity required.'}
 function Get-Candidates {$lease=[CornerAccess]::Exact([uint32]$cfg.TargetPid,[uint64]$cfg.TargetBirth,$cfg.TargetPath);if(!$lease){return};try{foreach($h in [SquareWindows]::Windows()){$id=Get-Identity $h;if($id -and $id.Pid -eq $cfg.TargetPid -and $id.Class -eq 'CodexCornerFixture'){$id}}}finally{$lease.Dispose()}}
 # Include only the hidden owned fixture, never other user windows.
 Add-Type -TypeDefinition 'using System;using System.Collections.Generic;using System.Runtime.InteropServices;public static class OwnElevatedFixtureWindows{delegate bool E(IntPtr h,IntPtr p);[DllImport("user32.dll")]static extern bool EnumWindows(E e,IntPtr p);public static long[] All(){var x=new List<long>();EnumWindows((h,p)=>{x.Add(h.ToInt64());return true;},IntPtr.Zero);return x.ToArray();}}'
 function Get-Candidates {$lease=[CornerAccess]::Exact([uint32]$cfg.TargetPid,[uint64]$cfg.TargetBirth,$cfg.TargetPath);if(!$lease){return};try{foreach($h in [OwnElevatedFixtureWindows]::All()){$id=Get-Identity $h;if($id -and $id.Pid -eq $cfg.TargetPid -and $id.Class -eq 'CodexCornerFixture'){$id}}}finally{$lease.Dispose()}}
}else{
 function Get-Candidates {foreach($id in & $baseCandidates){$lease=[CornerAccess]::Read([uint32]$id.Pid);if(!$lease){continue};try{if($lease.Integrity -ge 12288 -and $lease.Integrity -lt 16384){$id}}finally{$lease.Dispose()}}}
}
try {
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true};if(!$held){throw 'Elevated journal already controlled.'}
 # Production has one distinct high-scope journal; fixture has a private nonce
 # journal and cannot recover user windows.
 Restore-Windows
 if(@(Read-Journal).Count){throw 'Prior restoration incomplete.'}
 if($RecoverOnly){$status.Status='stopped';Write-Json $cfg.Status $status;return}
 $status.Status='running';Write-Json $cfg.Status $status
 while(!(Test-Path -LiteralPath $cfg.Cancel)) {Set-Square;Start-Sleep -Milliseconds 350}
}catch{$status.Status='failed';$status.Error=$_.Exception.Message;throw}
finally{try{if($held){Restore-Windows;$status.Remaining=@(Read-Journal).Count;$status.Status=if($status.Remaining){'restore-incomplete'}elseif($status.Error){'failed-restored'}else{'stopped'};Write-Json $cfg.Status $status}}finally{if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}}
