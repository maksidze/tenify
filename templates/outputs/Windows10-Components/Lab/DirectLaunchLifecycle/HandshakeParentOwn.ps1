param([string]$Directory)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lifecycle.ps1')
. (Join-Path $script:DirectLifecycleBase 'Launch-NonUiProcess.ps1')
$script:DirectLifecycleBase=Join-Path $PSScriptRoot ('parent-'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($script:DirectLifecycleBase)|Out-Null
$path=New-DirectStartup -Seconds 20;$worker=$null
try{
 $worker=Start-NonUiProcess -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'HandshakeWorker.ps1'),'-StartupState',$path,'-FixtureBase',$script:DirectLifecycleBase,'-Directory',$Directory) -RedirectStandardOutput (Join-Path $Directory 'worker.stdout') -RedirectStandardError (Join-Path $Directory 'worker.stderr')
 Write-DirectMarkerJson (Join-Path $Directory 'parent-ready.json') @{Worker=@{Pid=$worker.Id;Birth=[string]$worker.BirthFileTime;Path=(Join-Path $PSHOME 'powershell.exe')};StartupState=$path}
 if(!$worker.WaitForExit(25000)){throw 'Own handshake child deadline'}
}finally{if($worker){if(!$worker.HasExited){$worker.Kill();[void]$worker.WaitForExit(5000)};$worker.Dispose()}}
