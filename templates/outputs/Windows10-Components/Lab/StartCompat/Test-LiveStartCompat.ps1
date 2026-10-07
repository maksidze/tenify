param([int]$Seconds=25,[switch]$UseNativePath)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
$package=Get-AppxPackage -Name Microsoft.Windows.StartMenuExperienceHost
if(-not $package){throw 'Native Start package is not registered.'}
$nativePath=Join-Path $package.InstallLocation 'StartMenuExperienceHost.exe'
$native=@(Get-CimInstance Win32_Process -Filter "Name = 'StartMenuExperienceHost.exe'" | Where-Object {$_.ExecutablePath -ieq $nativePath})
if($native.Count -ne 1){throw 'Exactly one native Start process is required to identify the baseline.'}
$server=[regex]::Match($native[0].CommandLine,'-ServerName:\S+').Value
if(-not $server){throw 'Native Start command line has no observed server name.'}
$target=Join-Path $PSScriptRoot 'StartMenuExperienceHost.exe'
if($UseNativePath){$target=$nativePath}else{Copy-Item -LiteralPath $nativePath -Destination $target}
if((Get-AuthenticodeSignature -LiteralPath $target).Status -ne 'Valid'){throw 'Staged host signature is not valid.'}
$id=[Guid]::NewGuid().ToString('N').Substring(0,12)
$states=Join-Path $PSScriptRoot 'state';New-Item -ItemType Directory -Path $states -Force | Out-Null
$statePath=Join-Path $states "$id.json"
$report=Join-Path $PSScriptRoot "live-host-$id.log"
$start=[DateTime]::UtcNow
[pscustomobject]@{StartUtc=$start.ToString('o');DeadlineUtc=$start.AddSeconds($Seconds+20).ToString('o');TestPath=$target;NativePath=$nativePath;NativePathMode=[bool]$UseNativePath;NativePid=[int]$native[0].ProcessId;NativeCreationUtc=$native[0].CreationDate.ToUniversalTime().ToString('o');PackageFamily=$package.PackageFamilyName;ServerArgument=$server;Report=$report} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
$powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$restore=Join-Path $PSScriptRoot 'Restore-StartCompat.ps1'
$guard=Start-Process -FilePath $powershell -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -StatePath "{1}" -Guard' -f $restore,$statePath) -WindowStyle Hidden -PassThru
try {
 $check=Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $native[0].ProcessId)
 if(-not $check -or $check.ExecutablePath -ine $nativePath -or $check.CreationDate -ne $native[0].CreationDate){throw 'Native Start process changed before test.'}
 Stop-Process -Id $native[0].ProcessId -Force
 $probe=Join-Path $PSScriptRoot 'StartCompatHostProbe.exe'
 $arguments='"{0}" "{1}" {2} "{3}" --live' -f $report,$target,$Seconds,$server
 if($UseNativePath){$arguments+=' "'+(Join-Path $PSScriptRoot 'wincorlib.dll')+'"'}
 Invoke-CommandInDesktopPackage -PackageFamilyName $package.PackageFamilyName -AppId App -Command $probe -Args $arguments -PreventBreakaway
 $deadline=[DateTime]::UtcNow.AddSeconds($Seconds+5)
 while([DateTime]::UtcNow -lt $deadline){
  if((Test-Path -LiteralPath $report) -and ((Get-Content -LiteralPath $report -Raw) -match 'COMPLETE|EXIT code=')){break}
  Start-Sleep -Milliseconds 200
 }
} finally {
 [IO.File]::WriteAllText($statePath+'.restore','Restore requested by live test supervisor')
 & $restore -StatePath $statePath
}
Write-Output "State=$statePath"
Write-Output "Report=$report"
Get-Content -LiteralPath ($statePath+'.restored.json')

