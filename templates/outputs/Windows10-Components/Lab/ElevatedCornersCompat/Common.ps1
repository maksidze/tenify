$ErrorActionPreference='Stop'
$data=Join-Path $PSScriptRoot 'state'
[IO.Directory]::CreateDirectory($data)|Out-Null
if(-not ('CornerAccess' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'Access.cs')}
. (Join-Path $PSScriptRoot 'Launch-NonUiProcess.ps1')
if(-not ('CornerAtomic' -as [type])){Add-Type -TypeDefinition 'using System.IO;public static class CornerAtomic{public static void Save(string path,byte[] bytes){string temp=path+".tmp";using(var f=new FileStream(temp,FileMode.Create,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){f.Write(bytes,0,bytes.Length);f.Flush(true);}if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);}}'}
function Read-Json([string]$path){if(Test-Path -LiteralPath $path){Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json}}
function Journal-Count([string]$path){$entries=Read-Json $path;if($null -eq $entries){return 0};@($entries).Count}
function Write-Json([string]$path,$value){$bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $value -Depth 10));[CornerAtomic]::Save($path,$bytes)}
function Validate-Config([string]$path){$c=Read-Json $path;if(!$c -or $c.Format -ne 1 -or $c.Session -notmatch '^[a-f0-9]{32}$' -or [IO.Path]::GetFullPath($path) -ine (Join-Path $data ($c.Session+'.config.json'))){throw 'Invalid elevated-corner config identity.'};foreach($k in 'Cancel','Status'){if([IO.Path]::GetFullPath($c.$k) -ine (Join-Path $data ($c.Session+'.'+@{Cancel='cancel';Status='status.json'}[$k]))){throw 'Config path escapes private session.'}};$expectedJournal=if($c.Scope -eq 'Fixture'){Join-Path $data ($c.Session+'.journal.json')}else{Join-Path $data 'high-journal.json'};if([IO.Path]::GetFullPath($c.Journal) -ine $expectedJournal){throw 'Wrong journal scope.'};$c}
function Exact-Host($r){if(!$r -or !$r.Pid -or !$r.Birth -or $r.Path -ine (Join-Path $PSScriptRoot 'ElevatedCornerHost.exe')){return $null};[CornerAccess]::Exact([uint32]$r.Pid,[uint64]$r.Birth,$r.Path)}
