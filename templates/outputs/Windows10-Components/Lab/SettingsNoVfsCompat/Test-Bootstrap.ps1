$ErrorActionPreference='Stop'
$pkg=Get-AppxPackage windows.immersivecontrolpanel
$app=(Get-AppxPackageManifest $pkg).Package.Applications.Application.Id
$pythonw='@PYTHON_DIR@\pythonw.exe'
Invoke-CommandInDesktopPackage -PackageFamilyName $pkg.PackageFamilyName -AppId $app -Command $pythonw -Args ('"'+(Join-Path $PSScriptRoot 'Test-Bootstrap.py')+'"') -PreventBreakaway
$limit=[DateTime]::UtcNow.AddSeconds(35)
$proof=Join-Path $PSScriptRoot 'bootstrap-own-proof.json'
while([DateTime]::UtcNow -lt $limit -and !(Test-Path -LiteralPath $proof)){Start-Sleep -Milliseconds 100}
Get-Content -LiteralPath $proof -Raw
