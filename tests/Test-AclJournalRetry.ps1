param([string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(!$OutputDirectory){$OutputDirectory=Join-Path $env:TEMP ('b013-journal-test-'+[guid]::NewGuid().ToString('N'))}
[IO.Directory]::CreateDirectory($OutputDirectory)|Out-Null
Add-Type 'using System; using System.IO; using System.Threading; public static class ReceiptLockFixture { public static void ReleaseSoon(FileStream f) { new Thread(() => { Thread.Sleep(250); f.Dispose(); }).Start(); } }'
$root=Split-Path $PSScriptRoot
$results=@()
foreach($item in @(@('StartCompat/Grant-StartRuntimeAccess.ps1','Save-Receipt'),@('SettingsNoVfsSessionCompat/SourceAccess.ps1','Save-Journal'))){
 $path=Join-Path $root ('templates/outputs/Windows10-Components/Lab/'+$item[0]);$tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
 $function=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $item[1]},$true)
 . ([scriptblock]::Create($function.Extent.Text))
 $receipt=Join-Path $OutputDirectory ($item[1]+'.json')
 [IO.File]::WriteAllText($receipt,'[]');[IO.File]::WriteAllText($receipt+'.previous','[]')
 $held=[IO.File]::Open($receipt+'.previous',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 [ReceiptLockFixture]::ReleaseSoon($held)
 $timer=[Diagnostics.Stopwatch]::StartNew()
 try{& $item[1] @([pscustomobject]@{Path='fixture';Before='unchanged';After='recorded'})}finally{$held.Dispose()}
 $timer.Stop();$data=Get-Content -LiteralPath $receipt -Raw|ConvertFrom-Json
 if($data.Path -ne 'fixture' -or $timer.ElapsedMilliseconds -lt 150){throw 'Journal lock fixture did not exercise retry'}
 $results+=@{Function=$item[1];Passed=$true;ElapsedMilliseconds=$timer.ElapsedMilliseconds}
}
$results|ConvertTo-Json|Set-Content (Join-Path $OutputDirectory 'proof.json') -Encoding UTF8
$results|ConvertTo-Json
