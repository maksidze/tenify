param([string]$MediaPath,[int]$Index=0,[string]$OutputPath,[string]$PythonPath,[string]$ZigPath,[string]$SevenZipPath)
$ErrorActionPreference='Stop'
if(!$MediaPath){$MediaPath=Read-Host 'Path to the mounted Windows 10 installation disk (example D:\)'}
if(!$OutputPath){$OutputPath=Join-Path $env:USERPROFILE 'W10-b013'}
$OutputPath=[IO.Path]::GetFullPath($OutputPath)
if($OutputPath.StartsWith([IO.Path]::GetFullPath($env:WINDIR)+ '\',[StringComparison]::OrdinalIgnoreCase)){throw 'Output must not be inside Windows'}
$marker=Join-Path $OutputPath '.b013-builder-owned.json'
if(Test-Path -LiteralPath $OutputPath){
 if(!(Test-Path -LiteralPath $marker)){throw 'Output folder already exists and is not owned by this builder. Choose a new empty path.'}
}else{[IO.Directory]::CreateDirectory($OutputPath)|Out-Null}
[IO.File]::WriteAllText($marker,('{"Version":"b013","Workspace":'+($OutputPath|ConvertTo-Json -Compress)+'}'),[Text.UTF8Encoding]::new($false))
$tools=& (Join-Path $PSScriptRoot 'tools/bootstrap-tools.ps1') -PythonPath $PythonPath -ZigPath $ZigPath -SevenZipPath $SevenZipPath | Where-Object { $_.PSObject.Properties.Name -contains 'PythonPath' } | Select-Object -Last 1
if(!$tools){throw 'Dependency tools were not returned'}
$oldPath=$env:PYTHONPATH
try{
 $env:PYTHONPATH=Join-Path $PSScriptRoot '.tools/python-libs'
 & $tools.PythonPath (Join-Path $PSScriptRoot 'tools/build.py') --workspace $OutputPath --zig $tools.ZigPath --validate-only
 if($LASTEXITCODE -ne 0){throw 'Host compatibility check failed; extraction and shell transition not performed'}
 $list=Join-Path $OutputPath 'media-files.txt'
 $media=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'packaging/media-files.json') -Raw -Encoding UTF8 | ConvertFrom-Json
 [IO.File]::WriteAllLines($list,@($media.PSObject.Properties.Name),[Text.UTF8Encoding]::new($false))
 & (Join-Path $PSScriptRoot 'tools/extract-media.ps1') -MediaPath $MediaPath -Index $Index -SevenZipPath $tools.SevenZipPath -PythonPath $tools.PythonPath -Destination (Join-Path $OutputPath 'outputs/Windows10-Components/Image') -ListPath $list
 & $tools.PythonPath (Join-Path $PSScriptRoot 'tools/build.py') --workspace $OutputPath --zig $tools.ZigPath
 if($LASTEXITCODE -ne 0){throw ('Build failed. See '+(Join-Path $OutputPath 'build-report.json'))}
 Write-Host ('Ready. Start: '+(Join-Path $OutputPath 'Start-Windows10.bat'))
}finally{$env:PYTHONPATH=$oldPath}
