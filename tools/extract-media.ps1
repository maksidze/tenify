param([Parameter(Mandatory=$true)][string]$MediaPath,[int]$Index=0,[Parameter(Mandatory=$true)][string]$SevenZipPath,[Parameter(Mandatory=$true)][string]$Destination,[Parameter(Mandatory=$true)][string]$ListPath,[string]$PythonPath)
$ErrorActionPreference='Stop'
if(!$PythonPath){throw 'Pass the private PythonPath returned by bootstrap-tools.ps1'}
& $PythonPath (Join-Path $PSScriptRoot 'extract-media.py') --media $MediaPath --index $Index --sevenzip $SevenZipPath --destination $Destination --list $ListPath
if($LASTEXITCODE -ne 0){throw 'Media extraction failed; the shell was not switched'}
