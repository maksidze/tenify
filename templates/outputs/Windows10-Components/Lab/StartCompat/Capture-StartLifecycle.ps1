param([ValidateRange(10,150)][int]$Seconds=120,[Parameter(Mandatory=$true)][string]$Prefix)
$ErrorActionPreference='Stop'
$session='StartCompatLifecycle_'+[Guid]::NewGuid().ToString('N').Substring(0,10)
$providerFile=$Prefix+'.providers.txt'
@'
{eb65a492-86c0-406a-bace-9912d595bd69} 0xFFFFFFFFFFFFFFFF 5
'@ | Set-Content -LiteralPath $providerFile -Encoding ASCII
$started=$false
$deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
$helper=Get-Process -Id $PID
$status=[pscustomobject]@{Session=$session;Provider='Microsoft-Windows-AppModel-Exec';HelperPid=$PID;HelperCreationUtc=$helper.StartTime.ToUniversalTime().ToString('o');DeadlineUtc=$deadline.ToString('o');Etl=$Prefix+'.etl';State='Preparing';PersistentLogConfigurationChanged=$false}
$status | ConvertTo-Json | Set-Content -LiteralPath ($Prefix+'.status.json') -Encoding UTF8
$powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$guardPath=Join-Path $PSScriptRoot 'Capture-StartLifecycleGuard.ps1'
$guard=Start-Process -FilePath $powershell -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Prefix "{1}"' -f $guardPath,$Prefix) -WindowStyle Hidden -PassThru
try {
 $guardDeadline=[DateTime]::UtcNow.AddSeconds(5)
 while([DateTime]::UtcNow -lt $guardDeadline -and -not(Test-Path -LiteralPath ($Prefix+'.guard-ready'))){Start-Sleep -Milliseconds 50}
 if(-not(Test-Path -LiteralPath ($Prefix+'.guard-ready'))){throw 'Independent ETW stop guard did not become ready.'}
 & logman.exe create trace $session -ets -o ($Prefix+'.etl') -f bincirc -max 16 -pf $providerFile *> ($Prefix+'.start.log')
 if($LASTEXITCODE -ne 0){throw ('ETW start failed. See '+$Prefix+'.start.log')}
 $started=$true
 $status.State='Tracing'
 $status | ConvertTo-Json | Set-Content -LiteralPath ($Prefix+'.status.json') -Encoding UTF8
 [IO.File]::WriteAllText($Prefix+'.ready',$session)
 while([DateTime]::UtcNow -lt $deadline -and -not(Test-Path -LiteralPath ($Prefix+'.stop'))){Start-Sleep -Milliseconds 250}
} catch {
 $_ | Out-String | Set-Content -LiteralPath ($Prefix+'.error.txt') -Encoding UTF8
} finally {
 if($started){& logman.exe stop $session -ets *> ($Prefix+'.stop.log')}
 $status.State='Stopped'
 $status | ConvertTo-Json | Set-Content -LiteralPath ($Prefix+'.status.json') -Encoding UTF8
 [IO.File]::WriteAllText($Prefix+'.finished',[DateTime]::UtcNow.ToString('o'))
}
if($started){
 $events=@(Get-WinEvent -Path ($Prefix+'.etl') -Oldest -ErrorAction SilentlyContinue)
 $targetPid=0;if(Test-Path -LiteralPath ($Prefix+'.target.json')){$targetPid=[int](Get-Content -LiteralPath ($Prefix+'.target.json') -Raw | ConvertFrom-Json).TargetPid}
 $selected=@($events | Where-Object {($_.Message -match 'StartMenuExperienceHost') -or (($_.Properties.Value -join '|') -match 'StartMenuExperienceHost') -or ($targetPid -gt 0 -and ($_.ProcessId -eq $targetPid -or @($_.Properties.Value | Where-Object {"$_" -eq "$targetPid"}).Count -gt 0))} | ForEach-Object {[pscustomobject]@{TimeUtc=$_.TimeCreated.ToUniversalTime().ToString('o');Id=$_.Id;Provider=$_.ProviderName;Pid=$_.ProcessId;Tid=$_.ThreadId;Message=$_.Message;Properties=@($_.Properties.Value)}})
 $selected | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath ($Prefix+'.start-events.json') -Encoding UTF8
 $selected | Format-List | Out-String -Width 300 | Set-Content -LiteralPath ($Prefix+'.start-events.txt') -Encoding UTF8
}
