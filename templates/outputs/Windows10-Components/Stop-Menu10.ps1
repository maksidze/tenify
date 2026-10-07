$ErrorActionPreference='Stop'
$stateRoot=Join-Path $PSScriptRoot 'Lab\StartCompat\state'
$active=@()
foreach($file in Get-ChildItem -LiteralPath $stateRoot -Filter 'broker-*.json') {
 if($file.Name -notmatch '^broker-[a-f0-9]{12}\.json$'){continue}
 if(Test-Path -LiteralPath ($file.FullName+'.restored.json')){continue}
 $state=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
 if(-not $state.PackageDebugMode -or -not $state.NativePathMode){continue}
 if([DateTime]::Parse($state.DeadlineUtc).ToUniversalTime() -lt [DateTime]::UtcNow){continue}
 $active+=$file
}
if(-not $active.Count){Write-Host 'No active Menu10 test session found.';exit 0}
foreach($file in $active){[IO.File]::WriteAllText($file.FullName+'.restore','Stop requested from Stop-Menu10.ps1')}
$deadline=[DateTime]::UtcNow.AddSeconds(25)
foreach($file in $active) {
 while(-not(Test-Path -LiteralPath ($file.FullName+'.restored.json')) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 200}
 if(-not(Test-Path -LiteralPath ($file.FullName+'.restored.json'))){throw ('Restoration has not yet been confirmed: '+$file.FullName)}
 $result=Get-Content -LiteralPath ($file.FullName+'.restored.json') -Raw | ConvertFrom-Json
 if(-not $result.NativePresent){throw 'The controller did not confirm a native Start process.'}
 Write-Host ('Native Start restored; PID '+($result.NativePids -join ', '))
}
