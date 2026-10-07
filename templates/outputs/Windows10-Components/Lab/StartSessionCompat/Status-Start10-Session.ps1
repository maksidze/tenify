param([string]$StatePath)
$ErrorActionPreference='Stop'
if(!$StatePath){$active=Join-Path $PSScriptRoot 'active-session.txt';if(!(Test-Path -LiteralPath $active)){Write-Output 'No recorded Start session.';return};$StatePath=[IO.File]::ReadAllText($active).Trim()}
$resolved=[IO.Path]::GetFullPath($StatePath);$allowed=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'sessions'))+'\'
if(!$resolved.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'State path is outside owned sessions.'}
$dir=[IO.Path]::GetDirectoryName($resolved)
foreach($name in @('status.json','running.json','restored.json','cleanup-pending.json','native-restore.json')){if(Test-Path -LiteralPath (Join-Path $dir $name)){Write-Output $name;Get-Content -LiteralPath (Join-Path $dir $name) -Raw}}
