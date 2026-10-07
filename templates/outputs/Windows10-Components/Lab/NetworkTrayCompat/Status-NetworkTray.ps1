param([string]$Record)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'Windows PowerShell 5 Desktop required.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
. (Join-Path $PSScriptRoot 'NetworkTrayState.ps1')
$owned=Read-OwnedNetworkState $Record
if(!$owned){[pscustomobject]@{Active=$false;LifecycleReady=$false;VisualVerified=$false};return}
try{[pscustomobject]@{Active=($null -ne $owned.Process);LifecycleReady=$owned.Ready;StopRequested=$owned.StopRequested;VisualVerified=$false;Record=$owned.Record;ChildPid=$owned.State.ChildPid;TargetPid=$owned.State.TargetPid}}finally{if($owned.Process){$owned.Process.Dispose()}}
