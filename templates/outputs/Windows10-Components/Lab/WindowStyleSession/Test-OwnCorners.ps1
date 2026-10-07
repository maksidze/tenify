$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$previous=Read-Json (Join-Path $data 'current.json');$active=Exact-Controller $previous
if($active){$active.Dispose();throw 'An existing corner controller is active; fixture refused.'}
if(@(Read-Journal).Count){throw 'Existing user baselines present; fixture refused.'}
$proof=Join-Path $data ('own-proof-'+[guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($proof)|Out-Null
$exe=Join-Path $PSScriptRoot 'CornerFixture.exe'
$fixture=Start-NonUiProcess -FilePath $exe -ArgumentList @($proof) -RedirectStandardOutput (Join-Path $proof 'fixture.log') -RedirectStandardError (Join-Path $proof 'fixture.err')
$terminalBefore=@(Get-Process WindowsTerminal -ErrorAction SilentlyContinue | ForEach-Object {[string]$_.Id+':'+[string]$_.StartTime.ToUniversalTime().ToFileTimeUtc()})
function Windows {Read-Json (Join-Path $proof 'windows.json')}
function Wait-Proof([scriptblock]$test){$end=[DateTime]::UtcNow.AddSeconds(15);do{try{if(&$test){return}}catch{};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $end);throw 'Own fixture assertion timed out.'}
function Start-Corners {
 & (Join-Path $PSScriptRoot 'WindowCorners.ps1') -Mode Enable -Seconds 60 -FixturePid $fixture.Id -FixtureBirth ([string]$fixture.BirthFileTime) -FixturePath $exe
 $r=Read-Json (Join-Path $data 'current.json')
 foreach($h in [SquareWindows]::Windows()){[uint32]$owner=0;[void][SquareWindows]::GetWindowThreadProcessId([IntPtr]$h,[ref]$owner);if($owner -eq $r.Pid){throw 'Controller unexpectedly owns a visible window.'}}
}
function Stop-Corners {& (Join-Path $PSScriptRoot 'WindowCorners.ps1') -Mode Disable}
$results=[ordered]@{OnlyOwnHiddenFixture=$true;FixturePid=$fixture.Id;StartedUtc=[DateTime]::UtcNow.ToString('o')}
try {
 Wait-Proof {$w=Windows;$w.ar -eq 0 -and $w.av -eq 2 -and $w.fv -eq 3 -and !$w.visibleA}
 Start-Corners
 Wait-Proof {$w=Windows;$w.av -eq 1 -and $w.fv -eq 3}
 [IO.File]::WriteAllText((Join-Path $proof 'new'),'Create second hidden window')
 Wait-Proof {$w=Windows;$w.b -ne 0 -and $w.bv -eq 1 -and !$w.visibleB -and $w.fv -eq 3}
 $results.NewWindowApplied=$true
 Stop-Corners
 Wait-Proof {$w=Windows;$w.av -eq 2 -and $w.bv -eq 3 -and $w.fv -eq 3}
 $results.StopRestoredOriginals=$true
 Start-Corners
 Wait-Proof {(Windows).av -eq 1 -and (Windows).bv -eq 1}
 $r=Read-Json (Join-Path $data 'current.json');$p=Exact-Controller $r
 if(!$p){throw 'Own crash target exact identity not found.'}
 try {$p.Kill();if(!$p.WaitForExit(5000)){throw 'Own controller failed to exit.'}}finally{$p.Dispose()}
 if(@(Read-Journal).Count -ne 2){throw 'Crash journal did not retain two baselines.'}
 Stop-Corners
 Wait-Proof {$w=Windows;$w.av -eq 2 -and $w.bv -eq 3 -and $w.fv -eq 3}
 $results.CrashRecoveryRestoredOriginals=$true
 # A window property is its lifetime proof. Remove only our fixture token:
 # restoration must refuse that HWND even if PID/class/thread still match.
 Start-Corners;Wait-Proof {(Windows).av -eq 1}
 $w=Windows;[void][SquareWindows]::RemoveProp([IntPtr][long]$w.a,$propName)
 Stop-Corners
 if((Windows).av -ne 1){throw 'Foreign/reused-token window was mutated during restore.'}
 $results.MissingTokenRefused=$true
 # Return fixture to baseline ourselves; this is not production restoration.
 [int]$value=2;[void][SquareWindows]::DwmSetWindowAttribute([IntPtr][long]$w.a,33,[ref]$value,4)
 $results.ForeignWindowUntouched=$true;$results.VisibleWindows=0;$results.ControllerVisibleWindows=0
 $terminalAfter=@(Get-Process WindowsTerminal -ErrorAction SilentlyContinue | ForEach-Object {[string]$_.Id+':'+[string]$_.StartTime.ToUniversalTime().ToFileTimeUtc()})
 if(@($terminalAfter|Where-Object {$_ -notin $terminalBefore}).Count){throw 'A new Terminal process appeared during the own fixture.'}
 $results.NewTerminalProcesses=0;$results.Success=$true
}finally{
 try {Stop-Corners}catch{$results.CleanupError=$_.Exception.Message}
 [IO.File]::WriteAllText((Join-Path $proof 'exit'),'Exit own fixture')
 if(!$fixture.WaitForExit(5000)){$fixture.Kill();$fixture.WaitForExit(5000)|Out-Null};$fixture.Dispose()
 $results.EndedUtc=[DateTime]::UtcNow.ToString('o');Write-AtomicJson (Join-Path $proof 'result.json') $results
}
ConvertTo-Json $results
