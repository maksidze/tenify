# Dot-source from Windows PowerShell 5.1. No shell or package registration changes.
function Start-Explorer10PackagedController {
 [CmdletBinding()]
 param(
  [Parameter(Mandatory=$true)][string]$Python,
  [Parameter(Mandatory=$true)][string]$Controller,
  [Parameter(Mandatory=$true)][string]$RunDirectory,
  [string[]]$ControllerArguments=@(),
  [string]$PackageName='windows.immersivecontrolpanel',
  [string]$AppId='microsoft.windows.immersivecontrolpanel',
  [ValidateRange(1,30)][int]$TimeoutSeconds=10
 )
 $ErrorActionPreference='Stop'
 if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1 for Invoke-CommandInDesktopPackage.'}
 $Python=(Get-Item -LiteralPath $Python).FullName
 $Controller=(Get-Item -LiteralPath $Controller).FullName
 if([IO.Path]::GetFileName($Python) -notin @('python.exe','pythonw.exe')){throw 'Expected a Python interpreter.'}
 if([IO.Path]::GetExtension($Controller) -ine '.py'){throw 'Expected a Python controller.'}
 $wrapper=Join-Path $PSScriptRoot 'Packaged-Controller.py'
 if(-not(Test-Path -LiteralPath $wrapper -PathType Leaf)){throw 'Package controller wrapper missing.'}
 [void](New-Item -ItemType Directory -Path $RunDirectory -Force)
 $RunDirectory=(Get-Item -LiteralPath $RunDirectory).FullName
 foreach($file in @('status.json','child-ready','packaged-controller.json')) {
  if(Test-Path -LiteralPath (Join-Path $RunDirectory $file)){throw 'Use a fresh, unique run directory; stale controller state is present.'}
 }
 if($ControllerArguments -contains '--run-directory'){throw 'RunDirectory is added by this function; omit --run-directory from ControllerArguments.'}
 $pkg=@(Get-AppxPackage -Name $PackageName)
 if($pkg.Count -ne 1){throw 'Exactly one current-user native package is required.'}
 $family=$pkg[0].PackageFamilyName
 $handshake=Join-Path $RunDirectory 'packaged-controller.json'
 $nonce=[guid]::NewGuid().ToString('N')
 # CRT quoting: escape backslashes preceding quotes or the closing quote.
 function Quote-ControllerArgument([string]$Value) {
  '"'+[regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"'
 }
 $tokens=@($wrapper,$handshake,$nonce,$family,$Controller,$RunDirectory)+$ControllerArguments+@('--run-directory',$RunDirectory)
 $arguments=($tokens | ForEach-Object {Quote-ControllerArgument $_}) -join ' '
 Invoke-CommandInDesktopPackage -PackageFamilyName $family -AppId $AppId -Command $Python -Args $arguments -PreventBreakaway | Out-Null
 $deadline=(Get-Date).AddSeconds($TimeoutSeconds)
 while(-not(Test-Path -LiteralPath $handshake)) {
  if((Get-Date) -gt $deadline){throw 'Packaged controller startup handshake timed out. Existing shell recovery remains owned by the caller.'}
  Start-Sleep -Milliseconds 100
 }
 $state=Get-Content -LiteralPath $handshake -Raw | ConvertFrom-Json
 if($state.nonce -ne $nonce -or $state.packageFamilyName -ine $family -or $state.controller -ine $Controller -or $state.runDirectory -ine $RunDirectory){throw 'Packaged controller startup identity mismatch.'}
 $process=Get-Process -Id ([int]$state.helperPid) -ErrorAction Stop
 if($process.Path -ine $Python -or $state.python -ine $Python){throw 'Packaged controller executable path mismatch.'}
 $info=Get-CimInstance Win32_Process -Filter ('ProcessId='+$process.Id)
 # The unpredictable nonce plus unique absolute handshake path binds this process
 # to this launch. The wrapper also verifies package identity before publishing.
 if(-not $info -or -not $info.CommandLine.Contains($nonce) -or -not $info.CommandLine.Contains($handshake)){throw 'Packaged controller command line mismatch.'}
 $process.Refresh()
 if($process.HasExited){throw 'Packaged controller exited during startup.'}
 # Open the process handle while it is alive; retain exit/lifetime information.
 [void]$process.Handle
 return $process
}
