param()
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'PS5 required'}
$pkg=Get-AppxPackage windows.immersivecontrolpanel
$app=(Get-AppxPackageManifest $pkg).Package.Applications.Application.Id
$log=Join-Path $PSScriptRoot 'factory-own.log'
$exe=Join-Path $PSScriptRoot 'FactoryFixture.exe'
if(Test-Path -LiteralPath $log){Remove-Item -LiteralPath $log}
Invoke-CommandInDesktopPackage -PackageFamilyName $pkg.PackageFamilyName -AppId $app -Command $exe -Args ('"'+$log+'"') -PreventBreakaway
$limit=[DateTime]::UtcNow.AddSeconds(18)
do{Start-Sleep -Milliseconds 100;$text=if(Test-Path -LiteralPath $log){Get-Content -LiteralPath $log -Raw}else{''}}while([DateTime]::UtcNow -lt $limit -and $text -notmatch 'COMPLETE')
if($text -notmatch 'COMPLETE'){throw 'Own factory fixture timed out/failed; no actual Settings UI was activated'}
Write-Output $text
