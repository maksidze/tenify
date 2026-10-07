$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Windows PowerShell 5 required.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
$marker=Join-Path $PSScriptRoot 'untilstop-current-state.txt'
if(!(Test-Path -LiteralPath $marker)){Write-Output 'No recorded UntilStop publisher.';return}
$statePath=[IO.Path]::GetFullPath([IO.File]::ReadAllText($marker).Trim())
if((Split-Path $statePath) -ine [IO.Path]::GetFullPath($PSScriptRoot) -or [IO.Path]::GetFileName($statePath) -notmatch '^publisher-untilstop-[0-9a-f]{32}\.log\.state\.json$'){throw 'Owned publisher state path differs.'}
$s=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
if($s.Mode -ne 'UntilStop' -or ($s.Report+'.state.json') -cne $statePath -or $s.CancelFile -cne ($s.Report+'.cancel')){throw 'Publisher cancellation identity differs.'}
$controller=Get-Process -Id $s.ControllerPid -ErrorAction SilentlyContinue
if($controller -and ($controller.Path -ine (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -or $controller.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [long]$s.ControllerBorn)){throw 'Recorded controller identity was reused; cancellation refused.'}
if($s.Status -in @('stopped','failed')){Write-Output 'Recorded publisher is already terminal.';return}
[IO.File]::WriteAllText($s.CancelFile,'Explicit Stop requested')
$until=[DateTime]::UtcNow.AddSeconds(20)
do{
 $p=Get-Process -Id $s.PublisherPid -ErrorAction SilentlyContinue
 if(!$p -or $p.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [long]$s.PublisherBorn){Write-Output 'Exact recorded publisher exited; no shell process was stopped.';return}
 Start-Sleep -Milliseconds 200
}while([DateTime]::UtcNow -lt $until)
throw 'Owned publisher cleanup pending; retained native watchdog/Job owns termination. No unrelated process was killed.'
