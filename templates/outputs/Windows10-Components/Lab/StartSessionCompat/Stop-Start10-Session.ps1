param([string]$StatePath)
$ErrorActionPreference='Stop'
$base=Split-Path (Split-Path $PSScriptRoot)
. (Join-Path $base 'Launch-NonUiProcess.ps1')
if(!$StatePath){$active=Join-Path $PSScriptRoot 'active-session.txt';if(!(Test-Path -LiteralPath $active)){Write-Output 'No recorded Start session.';return};$StatePath=[IO.File]::ReadAllText($active).Trim()}
$resolved=[IO.Path]::GetFullPath($StatePath);$allowed=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'sessions'))+'\'
if(!$resolved.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'State path is outside owned sessions.'}
$state=Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
if([IO.Path]::GetFullPath($state.Directory) -ne [IO.Path]::GetDirectoryName($resolved) -or [IO.Path]::GetFullPath($state.CancelFile) -ne (Join-Path ([IO.Path]::GetDirectoryName($resolved)) 'cancel')){throw 'State paths differ from owned session.'}
[IO.File]::WriteAllText($state.CancelFile,'Explicit Stop requested')
if(Test-Path -LiteralPath (Join-Path $state.Directory 'restored.json')){Write-Output (Join-Path $state.Directory 'restored.json');return}
$python='@PYTHON_DIR@\python.exe'
$stop=Start-NonUiProcess -FilePath $python -ArgumentList @((Join-Path $PSScriptRoot 'SessionController.py'),'restore',$resolved) -RedirectStandardOutput ($resolved+'.stop.log') -RedirectStandardError ($resolved+'.stop.err')
try{if(!$stop.WaitForExit(55000)){throw 'Cleanup still pending; cancellation persists and independent guard remains responsible.'};if($stop.ExitCode -ne 0){throw ('Cleanup refused/failed: '+[IO.File]::ReadAllText($resolved+'.stop.err'))}}finally{$stop.Dispose()}
Write-Output (Join-Path $state.Directory 'restored.json')
