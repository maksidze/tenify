[CmdletBinding(DefaultParameterSetName='UntilStop')]
param([Parameter(ParameterSetName='UntilStop')][switch]$UntilStop,[Parameter(Mandatory=$true,ParameterSetName='Bounded')][ValidateRange(5,3600)][int]$Seconds,[switch]$PreflightOnly,[int]$TargetPid=0)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
$env:PSModulePath=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules'
$base=Split-Path (Split-Path $PSScriptRoot)
. (Join-Path $base 'Launch-NonUiProcess.ps1')
$python='@PYTHON_DIR@\python.exe'
$package=Get-AppxPackage -Name Microsoft.Windows.StartMenuExperienceHost
if(!$package -or @($package).Count -ne 1){throw 'Native Start package missing or ambiguous.'}
$native=Join-Path $package.InstallLocation 'StartMenuExperienceHost.exe'
& (Join-Path $base 'Lab/StartCompat/Grant-StartRuntimeAccess.ps1') | Out-Host
$processes=@(Get-CimInstance Win32_Process -Filter "Name = 'StartMenuExperienceHost.exe'" | Where-Object {$_.ExecutablePath -ieq $native})
$server=''
if($processes){$server=[regex]::Match($processes[0].CommandLine,'-ServerName:\S+').Value}
if(!$server){
 $previous=Get-ChildItem -LiteralPath (Join-Path $base 'Lab\StartCompat\state') -Filter 'broker-*.json' | Where-Object {$_.Name -match '^broker-[a-f0-9]+\.json$'} | Sort-Object LastWriteTime -Descending | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json} | Where-Object {$_.PackageFullName -eq $package.PackageFullName -and $_.ServerArgument} | Select-Object -First 1
 $server=$previous.ServerArgument
}
if(!$server){throw 'No previously observed genuine Start server argument for this package.'}
$nonce=[guid]::NewGuid().ToString('N');$directory=Join-Path $PSScriptRoot ('sessions\'+$nonce)
New-Item -ItemType Directory -Path $directory | Out-Null
$config='s_'+$nonce+'.ini';$debugger=Join-Path $PSScriptRoot 'Start10SessionDebugger.exe'
if($debugger.Contains(' ')){throw 'Verified package debugger path must have no spaces.'}
$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Raw | ConvertFrom-Json
$persistent=$PSCmdlet.ParameterSetName -eq 'UntilStop'
$state=@{Nonce=$nonce;Directory=$directory;CancelFile=(Join-Path $directory 'cancel');Seconds=$(if($persistent){30}else{$Seconds});UntilStop=$persistent;NativePath=$native;PackageFullName=$package.PackageFullName;PackageFamily=$package.PackageFamilyName;ServerArgument=$server;ConfigName=$config;DebuggerCommand=($debugger+' --session '+$config);Proxy=(Join-Path $base 'Lab\StartCompat\wincorlib.dll');Files=@($manifest.Files);RequestedExplorerPid=$TargetPid}
$prepared=Join-Path $directory 'prepared.json'
$state | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $prepared -Encoding UTF8
$prep=Start-NonUiProcess -FilePath $python -ArgumentList @((Join-Path $PSScriptRoot 'PrepareSession.py'),$prepared) -RedirectStandardOutput (Join-Path $directory 'preflight.json') -RedirectStandardError (Join-Path $directory 'preflight.err')
try{if(!$prep.WaitForExit(20000)){$prep.Kill();throw 'Preflight timed out.'};if($prep.ExitCode -ne 0){throw ('Preflight failed: '+[IO.File]::ReadAllText((Join-Path $directory 'preflight.err')))}}finally{$prep.Dispose()}
if($PreflightOnly){Write-Output $prepared;return}
$owner=Start-NonUiProcess -FilePath $python -ArgumentList @((Join-Path $PSScriptRoot 'SessionController.py'),'begin',$prepared) -RedirectStandardOutput (Join-Path $directory 'controller.log') -RedirectStandardError (Join-Path $directory 'controller.err')
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(50)
 while(!(Test-Path -LiteralPath (Join-Path $directory 'running.json'))){
  if($owner.HasExited -or [DateTime]::UtcNow -ge $deadline){[IO.File]::WriteAllText($state.CancelFile,'Enable failed or timed out');throw ('Start controller did not become ready: '+[IO.File]::ReadAllText((Join-Path $directory 'controller.err')))}
  Start-Sleep -Milliseconds 100
 }
 [pscustomobject]@{StatePath=(Join-Path $directory 'state.json');ControllerPid=$owner.Id;UntilStop=$persistent;BootstrapReady=$true;VisibleUIConfirmed=$false}
}finally{$owner.Dispose()}
