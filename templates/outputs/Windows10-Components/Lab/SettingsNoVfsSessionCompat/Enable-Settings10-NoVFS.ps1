param([switch]$PreflightOnly,[switch]$Diagnostic,[switch]$XamlFactory)
$ErrorActionPreference='Stop'
if($Diagnostic -and $XamlFactory){throw 'Choose diagnostic pass-through or scoped XAML candidate'}
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Windows PowerShell 5.1 required'}
Import-Module "$PSHOME\Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1"
Import-Module "$PSHOME\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1"
$base=Split-Path (Split-Path $PSScriptRoot)
. (Join-Path $base 'Launch-NonUiProcess.ps1')
$python='@PYTHON_DIR@\python.exe'
$receipts=Join-Path $PSScriptRoot 'acl-receipts';[IO.Directory]::CreateDirectory($receipts)|Out-Null
$receipt=Join-Path $receipts ([guid]::NewGuid().ToString('N')+'.json')
& (Join-Path $PSScriptRoot 'SourceAccess.ps1') -Receipt $receipt
$prep=Join-Path $PSScriptRoot ('prepare-'+[guid]::NewGuid().ToString('N'))
$prepareArgs=@((Join-Path $PSScriptRoot 'Prepare.py'));if($Diagnostic){$prepareArgs+='--diagnostic'}else{$prepareArgs+='--xaml-factory'}
$p=Start-NonUiProcess -FilePath $python -ArgumentList $prepareArgs -RedirectStandardOutput ($prep+'.txt') -RedirectStandardError ($prep+'.err')
try{if(!$p.WaitForExit(15000)){$p.Kill();throw 'Prepare timeout'};if($p.ExitCode){throw (Get-Content ($prep+'.err') -Raw)}}finally{$p.Dispose()}
$statePath=(Get-Content ($prep+'.txt') -Raw).Trim();$state=Get-Content $statePath -Raw|ConvertFrom-Json;$dir=$state.Directory
$p=Start-NonUiProcess -FilePath $python -ArgumentList @((Join-Path $PSScriptRoot 'SessionController.py'),'preflight',$statePath) -RedirectStandardOutput (Join-Path $dir 'preflight.json') -RedirectStandardError (Join-Path $dir 'preflight.err')
try{if(!$p.WaitForExit(15000)){$p.Kill();throw 'Preflight timeout'};if($p.ExitCode){throw (Get-Content (Join-Path $dir 'preflight.err') -Raw)}}finally{$p.Dispose()}
$pre=Get-Content (Join-Path $dir 'preflight.json') -Raw|ConvertFrom-Json
if(@($pre.Conflicts).Count){throw 'Settings package is already open; close it before enabling. Existing process preserved.'}
if($PreflightOnly){Write-Output $statePath;return}
$p=Start-NonUiProcess -FilePath $python -ArgumentList @((Join-Path $PSScriptRoot 'SessionController.py'),'begin',$statePath) -RedirectStandardOutput (Join-Path $dir 'controller.log') -RedirectStandardError (Join-Path $dir 'controller.err')
try{$until=[DateTime]::UtcNow.AddSeconds(20);while(!(Test-Path (Join-Path $dir 'enabled.json'))){if($p.HasExited -or [DateTime]::UtcNow -ge $until){[IO.File]::WriteAllText($state.CancelFile,'enable timeout');throw (Get-Content (Join-Path $dir 'controller.err') -Raw)};Start-Sleep -Milliseconds 100};Write-Output (Join-Path $dir 'state.json')}finally{$p.Dispose()}
