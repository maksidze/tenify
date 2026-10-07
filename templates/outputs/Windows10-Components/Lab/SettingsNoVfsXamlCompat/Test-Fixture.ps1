$ErrorActionPreference='Stop'
$pkg=Get-AppxPackage windows.immersivecontrolpanel;$app=(Get-AppxPackageManifest $pkg).Package.Applications.Application.Id
$log=Join-Path $PSScriptRoot 'own-xaml.log';if(Test-Path $log){Remove-Item -LiteralPath $log}
Invoke-CommandInDesktopPackage -PackageFamilyName $pkg.PackageFamilyName -AppId $app -Command (Join-Path $PSScriptRoot 'Fixture.exe') -Args ('"'+$log+'" "'+(Join-Path $PSScriptRoot 'SettingsFactorySelectorXaml.dll')+'"') -PreventBreakaway
$limit=[DateTime]::UtcNow.AddSeconds(18)
do{Start-Sleep -Milliseconds 100;$text=if(Test-Path $log){Get-Content $log -Raw}else{''}}while([DateTime]::UtcNow -lt $limit -and $text -notmatch 'COMPLETE')
if($text -notmatch 'COMPLETE'){throw ('Own nativeXAML IAT fixture failed: '+($text -split "`n"|Select-Object -Last 15|Out-String))}
Write-Output 'Actual nativeXAML IAT + genuine factories/canaries complete; no UI'
