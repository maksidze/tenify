param([string]$Record)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'Windows PowerShell 5 Desktop required.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
. (Join-Path $PSScriptRoot 'NetworkTrayState.ps1')
$owned=Read-OwnedNetworkState $Record
if(!$owned){Write-Output 'No owned network session.';return}
if(!$owned.Process){Write-Output 'Recorded network helper already exited.';return}
try{
 & (Join-Path $PSScriptRoot '..\NetworkTrayVisibilityCompat\Set-NetworkVisibility.ps1') -Action Restore -StateFile $Record
 [IO.File]::WriteAllText($owned.State.StopFile,'cancel')
 if(!$owned.Process.WaitForExit(12000)){throw 'Owned helper did not finish its bounded cleanup; parent Job/native watchdog remains responsible. No process was forcibly terminated.'}
 Write-Output ('Owned network helper stopped. Exit='+$owned.Process.ExitCode)
}finally{$owned.Process.Dispose()}
