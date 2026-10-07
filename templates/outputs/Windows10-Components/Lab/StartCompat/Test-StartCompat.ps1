param([ValidateSet('Factory','Host')][string]$Mode='Factory',[int]$Seconds=12,[string]$Class='')
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Run this script with Windows PowerShell 5.1.'}
$workspace=Split-Path (Split-Path $PSScriptRoot)
$package=Get-AppxPackage -Name Microsoft.Windows.StartMenuExperienceHost
if(-not $package){throw 'Native Start package is not registered.'}
$env:W10_STARTCOMPAT_ENABLE='1'
$stamp=[Guid]::NewGuid().ToString('N').Substring(0,8)
$pri=Join-Path $workspace 'Image\4\Windows\SystemResources\Windows.UI.ShellCommon\Windows.UI.ShellCommon.pri'
if($Mode -eq 'Factory'){
 $log=Join-Path $PSScriptRoot ("probe-proxy-packaged-$stamp.log")
 $exe=Join-Path $PSScriptRoot 'StartCompatProbe.exe'
 $proxy=Join-Path $PSScriptRoot 'wincorlib.dll'
 $arguments='"{0}" "{1}" "{2}"' -f $log,$proxy,$pri
 if($Class){if($Class -notmatch '^StartUI\.[A-Za-z0-9_.]+$'){throw 'Only a StartUI class can be probed.'};$arguments+=' --activate-class "'+$Class+'"'}
 Invoke-CommandInDesktopPackage -PackageFamilyName $package.PackageFamilyName -AppId App -Command $exe -Args $arguments -PreventBreakaway
 $deadline=[DateTime]::UtcNow.AddSeconds(15)
 while([DateTime]::UtcNow -lt $deadline){if((Test-Path -LiteralPath $log) -and ((Get-Content -Raw -LiteralPath $log) -match 'SUMMARY|UNHANDLED_EXCEPTION')){break};Start-Sleep -Milliseconds 100}
 if(Test-Path -LiteralPath $log){Get-Content -LiteralPath $log}
} else {
 $hostSource=Join-Path $package.InstallLocation 'StartMenuExperienceHost.exe'
 $target=Join-Path $PSScriptRoot 'StartMenuExperienceHost.exe'
 Copy-Item -LiteralPath $hostSource -Destination $target
 if((Get-AuthenticodeSignature -LiteralPath $target).Status -ne 'Valid'){throw 'Staged original StartMenuExperienceHost signature is not valid.'}
 $probe=Join-Path $PSScriptRoot 'StartCompatHostProbe.exe'
 $report=Join-Path $PSScriptRoot ("host-packaged-probe-$stamp.log")
 $arguments='"{0}" "{1}" {2}' -f $report,$target,$Seconds
 Invoke-CommandInDesktopPackage -PackageFamilyName $package.PackageFamilyName -AppId App -Command $probe -Args $arguments -PreventBreakaway
 $deadline=[DateTime]::UtcNow.AddSeconds($Seconds+15)
 while([DateTime]::UtcNow -lt $deadline){if((Test-Path -LiteralPath $report) -and ((Get-Content -Raw -LiteralPath $report) -match 'COMPLETE')){break};Start-Sleep -Milliseconds 200}
 if(Test-Path -LiteralPath $report){Get-Content -LiteralPath $report -Raw}else{throw 'Probe report was not produced.'}
}
