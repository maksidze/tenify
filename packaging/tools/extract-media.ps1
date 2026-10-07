[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$MediaPath,
 [int]$Index=0,
 [Parameter(Mandatory=$true)][string]$SevenZipPath,
 [Parameter(Mandatory=$true)][string]$Destination,
 [Parameter(Mandatory=$true)][string]$ListPath,
 [switch]$PlanOnly
)
$ErrorActionPreference='Stop'
function Full-LocalPath([string]$Path){
 if($Path -match '^[A-Za-z]:$'){$Path+='\'}
 $full=[IO.Path]::GetFullPath($Path)
 if($full -notmatch '^[A-Za-z]:\\'){throw 'Use an absolute local drive path.'}
 return $full
}
function Reject-Reparse([string]$Path){
 $current=$Path
 while($current){if(Test-Path -LiteralPath $current){if((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw ('Reparse-point output ancestor refused: '+$current)}};$parent=[IO.Path]::GetDirectoryName($current);if($parent -eq $current){break};$current=$parent}
}
function Quote-Argument([string]$Value){
 if($Value -notmatch '[\s"]' -and $Value){return $Value}
 # CreateProcess/CRT quoting, including embedded quotes and trailing backslashes.
 return '"'+([regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1'))+'"'
}
function Invoke-SevenZip([string[]]$Arguments,[int]$Seconds=600){
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName=$tool;$info.Arguments=($Arguments|ForEach-Object {Quote-Argument $_}) -join ' '
 $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $process=New-Object Diagnostics.Process;$process.StartInfo=$info
 $memory=New-Object IO.MemoryStream
 try{
  if(!$process.Start()){throw '7-Zip process creation failed.'}
  $output=$process.StandardOutput.BaseStream.CopyToAsync($memory);$errorText=$process.StandardError.ReadToEndAsync()
  if(!$process.WaitForExit($Seconds*1000)){$process.Kill();[void]$process.WaitForExit(5000);throw 'Exact owned 7-Zip extraction timed out.'}
  $output.GetAwaiter().GetResult();$stderr=$errorText.GetAwaiter().GetResult()
  if($process.ExitCode -notin @(0,1)){throw ('7-Zip failed '+$process.ExitCode+': '+$stderr)}
  return @{Code=$process.ExitCode;Bytes=$memory.ToArray();Error=$stderr}
 }finally{$memory.Dispose();$process.Dispose()}
}
$media=Full-LocalPath $MediaPath;$tool=Full-LocalPath $SevenZipPath;$list=Full-LocalPath $ListPath;$dest=Full-LocalPath $Destination
if(!(Test-Path -LiteralPath $tool -PathType Leaf) -or [IO.Path]::GetExtension($tool) -ine '.exe'){throw 'Supply an existing user-owned 7z.exe.'}
if(!(Test-Path -LiteralPath $list -PathType Leaf)){throw 'Extraction list absent.'}
if(Test-Path -LiteralPath $media -PathType Container){
 $candidates=@((Join-Path $media 'sources\install.wim'),(Join-Path $media 'sources\install.esd'))|Where-Object {Test-Path -LiteralPath $_ -PathType Leaf}
 if($candidates.Count -ne 1){throw 'Mounted installation media must contain exactly one sources\install.wim or install.esd.'};$archive=$candidates[0]
}elseif((Test-Path -LiteralPath $media -PathType Leaf) -and [IO.Path]::GetExtension($media) -in @('.wim','.esd')){$archive=$media}else{throw 'Supply mounted media directory or install.wim/install.esd; ISO mounting is outside this script.'}
if($dest.TrimEnd('\') -ieq [IO.Path]::GetPathRoot($dest).TrimEnd('\')){throw 'Drive root cannot be output.'}
foreach($protected in @($env:WINDIR,$env:ProgramFiles,${env:ProgramFiles(x86)})){
 if($protected -and ($dest -ieq $protected -or $dest.StartsWith($protected.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase))){throw 'System/program directory cannot be output.'}
}
Reject-Reparse $dest
if(Test-Path -LiteralPath $dest){if(!(Test-Path -LiteralPath $dest -PathType Container) -or @(Get-ChildItem -LiteralPath $dest -Force).Count){throw 'Destination must be absent or empty; no overwrite/cleanup of existing files is permitted.'}}
if($archive.StartsWith($dest.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $list.StartsWith($dest.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Inputs cannot reside under output.'}
$relative=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach($entry in [IO.File]::ReadAllLines($list)){
 $path=$entry.Trim().Replace('/','\');if(!$path){continue}
 $path=$path -replace '^\d+\\',''
 if($path -match '[\x00-\x1f:*?"<>|]' -or $path.StartsWith('\') -or $path -notmatch '^(Windows|Program Files)\\' -or @($path.Split('\')|Where-Object {$_ -in @('','.','..')}).Count){throw ('Unsafe/nonliteral archive path: '+$entry)}
 [void]$relative.Add($path)
}
if(!$relative.Count){throw 'Empty extraction selection.'}
$xmlResult=Invoke-SevenZip @('e','-so','-spd','--',$archive,'[1].xml') 60
$xmlStream=New-Object IO.MemoryStream -ArgumentList (,$xmlResult.Bytes)
try{$reader=[Xml.XmlReader]::Create($xmlStream);$document=New-Object Xml.XmlDocument;$document.Load($reader)}finally{if($reader){$reader.Dispose()};$xmlStream.Dispose()}
$compatible=@($document.WIM.IMAGE|Where-Object {$_.WINDOWS.EDITIONID -eq 'Professional' -and $_.WINDOWS.ARCH -eq '9' -and $_.WINDOWS.LANGUAGES.DEFAULT -eq 'ru-RU' -and $_.WINDOWS.VERSION.MAJOR -eq '10' -and $_.WINDOWS.VERSION.MINOR -eq '0' -and $_.WINDOWS.VERSION.BUILD -eq '19045' -and $_.WINDOWS.VERSION.SPBUILD -eq '5487'})
if($Index){$chosen=@($compatible|Where-Object {[int]$_.INDEX -eq $Index})}else{$chosen=$compatible}
if($chosen.Count -ne 1){throw 'Require one compatible Windows 10 Pro AMD64 ru-RU 10.0.19045.5487 image; unsupported media/index refused.'}
$selectedIndex=[int]$chosen[0].INDEX;$archivePaths=@($relative|Sort-Object|ForEach-Object {$selectedIndex.ToString()+'\'+$_})
$plan=[ordered]@{Version=1;Archive=$archive;Index=$selectedIndex;Edition='Professional';Architecture='AMD64';Language='ru-RU';Build='10.0.19045.5487';Destination=$dest;SelectedFiles=$archivePaths.Count;SevenZip=$tool;PlanOnly=[bool]$PlanOnly;NoGlobalMount=$true;NoSystemFilesChanged=$true}
if($PlanOnly){$plan|ConvertTo-Json;return}
[IO.Directory]::CreateDirectory($dest)|Out-Null;$generatedList=Join-Path $dest '.extract-list.txt';[IO.File]::WriteAllLines($generatedList,$archivePaths,(New-Object Text.UTF8Encoding($false)))
$listed=Invoke-SevenZip @('l','-slt','-sccUTF-8','-scsUTF-8','-spd',('-i@'+$generatedList),'--',$archive) 600
$records=@{};$record=@{}
foreach($line in ([Text.Encoding]::UTF8.GetString($listed.Bytes) -split "\r?\n")){
 if(!$line){if($record.Path -and $archivePaths -contains $record.Path){$records[$record.Path]=$record};$record=@{};continue}
 $split=$line.IndexOf(' = ');if($split -ge 0){$record[$line.Substring(0,$split)]=$line.Substring($split+3)}
}
if($record.Path -and $archivePaths -contains $record.Path){$records[$record.Path]=$record}
foreach($path in $archivePaths){if(!$records.ContainsKey($path) -or $records[$path].Folder -ne '-' -or $records[$path].Link -or $records[$path].'Alternate Stream' -eq '+' -or $records[$path].'SHA-1' -notmatch '^[0-9a-fA-F]{40}$'){throw ('Missing, linked, or unverifiable selected WIM file: '+$path)}}
$need=($records.Values|ForEach-Object {[uint64]$_.Size}|Measure-Object -Sum).Sum;$drive=New-Object IO.DriveInfo([IO.Path]::GetPathRoot($dest));if($drive.AvailableFreeSpace -lt $need+134217728){throw 'Insufficient free space for selective extraction.'}
$extracted=Invoke-SevenZip @('x','-y','-scsUTF-8','-spd',('-o'+$dest),'--',$archive,('@'+$generatedList)) 1800
$verified=@()
foreach($path in $archivePaths){
 $file=[IO.Path]::GetFullPath((Join-Path $dest $path));if(!$file.StartsWith($dest.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Output escaped destination.'};Reject-Reparse $file
 if(!(Test-Path -LiteralPath $file -PathType Leaf) -or (Get-Item -LiteralPath $file).Length -ne [long]$records[$path].Size -or (Get-FileHash -LiteralPath $file -Algorithm SHA1).Hash -ine $records[$path].'SHA-1'){throw ('Selected file size/WIM SHA1 mismatch: '+$path)}
 $verified+=@{ArchivePath=$path;Size=[long]$records[$path].Size;WimSHA1=$records[$path].'SHA-1';SHA256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash}
}
$plan.VerifiedFiles=$verified;$plan.ExtractionExit=$extracted.Code;$plan.Complete=$true
[IO.File]::WriteAllText((Join-Path $dest 'extraction-manifest.json'),($plan|ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)))
$plan|ConvertTo-Json -Depth 6
