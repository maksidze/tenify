$ErrorActionPreference='Stop'
$base=Split-Path (Split-Path $PSScriptRoot)
$data=Join-Path $PSScriptRoot 'state'
[IO.Directory]::CreateDirectory($data)|Out-Null
$journal=Join-Path $data 'journal.json'
. (Join-Path $base 'WindowStyle\WindowStyle.ps1') -Action Library -StatePath $journal
. (Join-Path $base 'Launch-NonUiProcess.ps1')
if(-not ('CornerJournal' -as [type])){Add-Type -TypeDefinition @'
using System.IO;
public static class CornerJournal {
 public static void Save(string path,byte[] bytes){string temp=path+".tmp";using(var f=new FileStream(temp,FileMode.Create,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){f.Write(bytes,0,bytes.Length);f.Flush(true);}if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);}
}
'@}
function Write-AtomicJson([string]$path,$value){
 $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $value -Depth 8))
 [CornerJournal]::Save($path,$bytes)
}
function Save-Journal($entries){Write-AtomicJson $journal @($entries)}
function Read-Json([string]$path){if(Test-Path -LiteralPath $path){Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json}}
function New-JournalMutex {
 $sha=[Security.Cryptography.SHA256]::Create()
 try {$hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($journal).ToLowerInvariant()))).Replace('-','')} finally {$sha.Dispose()}
 New-Object Threading.Mutex($false,('Local\CodexWindowStyle_'+$hash))
}
function Lock-Mutex($m,[int]$ms=0){try{return $m.WaitOne($ms)}catch [Threading.AbandonedMutexException]{return $true}}
function Exact-Controller($record){
 if(!$record -or !$record.Pid -or !$record.BirthFileTime -or !$record.Path){return $null}
 try {$p=Get-Process -Id ([int]$record.Pid) -ErrorAction Stop;if($p.Path -ieq $record.Path -and [string]$p.StartTime.ToUniversalTime().ToFileTimeUtc() -eq [string]$record.BirthFileTime){return $p};$p.Dispose()}catch{}
 return $null
}
