param(
 [ValidateSet('Setup','Restore','Status')][string]$Action='Setup',
 [string]$Journal,
 [switch]$SkipThumbnail
)
$ErrorActionPreference='Stop'
$lab=$PSScriptRoot
$base=Split-Path (Split-Path $lab -Parent) -Parent
. (Join-Path $base 'Launch-NonUiProcess.ps1')
$python='@PYTHON_DIR@\python.exe'
$arguments=@((Join-Path $lab 'Repair.py'),$Action.ToLowerInvariant())
if($Journal){$arguments+=@('--journal',$Journal)}
if($SkipThumbnail){$arguments+='--skip-thumbnail'}
$nonce=[Guid]::NewGuid().ToString('N')
$stdout=Join-Path $lab ($nonce+'.stdout.txt')
$stderr=Join-Path $lab ($nonce+'.stderr.txt')
$process=Start-NonUiProcess -FilePath $python -ArgumentList $arguments -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WorkingDirectory $lab
try{
 if(-not $process.WaitForExit(90000)){$process.Kill();$process.WaitForExit(5000)|Out-Null;throw 'Targeted icon supervisor exceeded 90 seconds. Its owned job closes automatically; inspect the durable journal.'}
 $code=$process.ExitCode
 if(Test-Path -LiteralPath $stdout){Get-Content -LiteralPath $stdout -Raw}
 if($code -ne 0){if(Test-Path -LiteralPath $stderr){Get-Content -LiteralPath $stderr -Raw};throw "Targeted icon repair failed ($code). See last-error.json and the journal."}
}finally{$process.Dispose()}
