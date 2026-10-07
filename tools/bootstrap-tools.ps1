param([string]$PythonPath,[string]$ZigPath,[string]$SevenZipPath)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$cache=Join-Path $repo '.tools'
[IO.Directory]::CreateDirectory($cache)|Out-Null
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
function Fetch([string]$Url,[string]$Name,[string]$Hash){
 $p=Join-Path $cache $Name
 if(!(Test-Path -LiteralPath $p) -or (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ine $Hash){
  Write-Host ('Downloading '+$Name)
  Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile ($p+'.download')
  if((Get-FileHash -LiteralPath ($p+'.download') -Algorithm SHA256).Hash -ine $Hash){throw ('Download checksum mismatch: '+$Name)}
  Move-Item -LiteralPath ($p+'.download') -Destination $p -Force
 }
 return $p
}
if(!$PythonPath){
 $zip=Fetch 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip' 'python-3.12.10-embed-amd64.zip' '4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3'
 $dir=Join-Path $cache 'python312'
 if(!(Test-Path -LiteralPath (Join-Path $dir 'python.exe'))){Expand-Archive -LiteralPath $zip -DestinationPath $dir}
 [IO.File]::WriteAllText((Join-Path $dir 'python312._pth'),"python312.zip`n.`n../python-libs`nimport site`n",[Text.UTF8Encoding]::new($false))
 $PythonPath=Join-Path $dir 'python.exe'
}
if(!$ZigPath){
 $zip=Fetch 'https://ziglang.org/download/0.15.2/zig-x86_64-windows-0.15.2.zip' 'zig-x86_64-windows-0.15.2.zip' '3a0ed1e8799a2f8ce2a6e6290a9ff22e6906f8227865911fb7ddedc3cc14cb0c'
 $dir=Join-Path $cache 'zig'
 if(!(Test-Path -LiteralPath (Join-Path $dir 'zig-x86_64-windows-0.15.2/zig.exe'))){Expand-Archive -LiteralPath $zip -DestinationPath $dir}
 $ZigPath=Join-Path $dir 'zig-x86_64-windows-0.15.2/zig.exe'
}
if(!$SevenZipPath){
 $zr=Fetch 'https://github.com/ip7z/7zip/releases/download/26.03/7zr.exe' '7zr.exe' 'ad4c82fadcbdf93c03b4fc440f300509c7d60c5c2f4d183e35d9d70d6957037d'
 $installer=Fetch 'https://github.com/ip7z/7zip/releases/download/26.03/7z2603-x64.exe' '7z2603-x64.exe' '0859c524b8a63551848f0c246abddcb1d0b7b656b0fbfe879f8d85e61a9e6edd'
 $dir=Join-Path $cache '7zip'
 if(!(Test-Path -LiteralPath (Join-Path $dir '7z.exe'))){
  & $zr x $installer ('-o'+$dir) -y | Out-Host
  if($LASTEXITCODE -ne 0){throw 'Portable 7-Zip unpack failed'}
 }
 $SevenZipPath=Join-Path $dir '7z.exe'
}
foreach($p in @($PythonPath,$ZigPath,$SevenZipPath)){if(!(Test-Path -LiteralPath $p -PathType Leaf)){throw ('Tool missing: '+$p)}}
& $PythonPath (Join-Path $PSScriptRoot 'fetch-python-packages.py')
if($LASTEXITCODE -ne 0){throw 'Python dependency bootstrap failed'}
[pscustomobject]@{PythonPath=[IO.Path]::GetFullPath($PythonPath);ZigPath=[IO.Path]::GetFullPath($ZigPath);SevenZipPath=[IO.Path]::GetFullPath($SevenZipPath)}
