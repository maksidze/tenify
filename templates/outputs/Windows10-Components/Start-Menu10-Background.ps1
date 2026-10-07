$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Launch-NonUiProcess.ps1')
$test=Join-Path $PSScriptRoot 'Lab\StartCompat\Test-BrokerStartCompat.ps1'
if(-not(Test-Path -LiteralPath $test)){throw 'Start test launcher is missing.'}
$logRoot=Join-Path $PSScriptRoot 'Lab\StartCompat\state'
$id=[guid]::NewGuid().ToString('N')
$out=Join-Path $logRoot ('menu-'+$id+'.stdout.txt')
$err=Join-Path $logRoot ('menu-'+$id+'.stderr.txt')
$child=Start-NonUiProcess -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -RedirectStandardOutput $out -RedirectStandardError $err -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$test,'-Seconds','3600','-DetachAfterBootstrap')
Write-Host ('Start requested; controller PID '+$child.Id+'. Use R to restore native Start.')
Write-Host ('Result log: '+$out)
Write-Host ('Error log: '+$err)
