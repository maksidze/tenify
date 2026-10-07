$lab=$PSScriptRoot
$pkg=Get-AppxPackage Microsoft.Windows.StartMenuExperienceHost
$exe=Join-Path $pkg.InstallLocation 'StartMenuExperienceHost.exe'
$log=Join-Path $lab 'native-path-injection-preflight.log'
$proxy=Join-Path $lab 'wincorlib.dll'
$probe=Join-Path $lab 'StartCompatHostProbe.exe'
$args='"{0}" "{1}" 10 "-StartCompat-Unregistered" --hidden "{2}"' -f $log,$exe,$proxy
Invoke-CommandInDesktopPackage -PackageFamilyName $pkg.PackageFamilyName -AppId App -Command $probe -Args $args -PreventBreakaway
