$ErrorActionPreference='Stop'
$lab=Join-Path $PSScriptRoot 'Lab\SettingsBrokerCompat'
$marker=Join-Path $lab 'manual-current-prepared.txt'
if(!(Test-Path -LiteralPath $marker)){Write-Host 'No manual Settings session marker.';return}
$preparedPath=[IO.File]::ReadAllText($marker).Trim()
[IO.File]::WriteAllText(($preparedPath+'.cancel'),'Manual cancellation requested')
$prepared=Get-Content -LiteralPath $preparedPath -Raw | ConvertFrom-Json
$states=@(Get-ChildItem -LiteralPath (Join-Path $lab 'state') -Filter 'settings-*.json' | Where-Object {$_.Name -notlike '*.restored.json'} | ForEach-Object {$state=Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json;if($state.Report -eq $prepared.Report){$_.FullName}})
if($states.Count -eq 0){Write-Host 'Startup cancellation recorded; no broker state exists yet.';return}
if($states.Count -ne 1){throw ('Expected one exact report-owned session; found '+$states.Count)}
if(Test-Path -LiteralPath ($states[0]+'.restored.json')){Write-Host 'This exact Settings session is already restored.';return}
[IO.File]::WriteAllText(($states[0]+'.restore'),'Manual stop requested')
& (Join-Path $lab 'Restore-SettingsBroker.ps1') -StatePath $states[0]
if(Test-Path -LiteralPath ($states[0]+'.restored.json')){Write-Host 'Exact owned session restored; package debugging disabled.'}else{Write-Host 'Cancellation recorded; startup/late-claim cleanup is pending in the owned supervisor.'}
