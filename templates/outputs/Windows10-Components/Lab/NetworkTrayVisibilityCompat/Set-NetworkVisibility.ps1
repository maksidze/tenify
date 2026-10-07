param([ValidateSet('Promote','Restore','Read')][string]$Action='Read',[string]$StateFile='')
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1')
$manifest=Get-Content (Join-Path $PSScriptRoot 'manifest.json') -Raw|ConvertFrom-Json
foreach($f in $manifest.Files){if((Get-FileHash $f.Path).Hash -ne $f.SHA256){throw 'Visibility helper build changed'}}
$network=Join-Path (Split-Path $PSScriptRoot) 'NetworkTrayUntilStopCompat'
if(!$StateFile){$StateFile=(Get-Content (Join-Path $network 'active-network-session.txt') -Raw).Trim()}
$s=Get-Content $StateFile -Raw|ConvertFrom-Json
. (Join-Path $network 'NetworkTrayState.ps1')
$owned=Read-OwnedNetworkState $StateFile
if(!$owned -or !$owned.Process -or !$owned.Ready -or $owned.StopRequested){throw 'Exact active network helper is not ready'}
$owned.Process.Dispose()
$path=$s.ChildPath.ToUpperInvariant();$sha=[Security.Cryptography.SHA256]::Create();$bytes=$sha.ComputeHash([Text.Encoding]::Unicode.GetBytes($path));$sha.Dispose();$guidBytes=New-Object byte[] 16;[Array]::Copy($bytes,$guidBytes,16);$v=[BitConverter]::ToUInt16($guidBytes,6);$fixed=[BitConverter]::GetBytes([uint16](($v -band 0xfff) -bor 0x5000));$guidBytes[6]=$fixed[0];$guidBytes[7]=$fixed[1];$guidBytes[8]=($guidBytes[8] -band 0x3f) -bor 0x80;$guid=New-Object Guid (,$guidBytes)
$nonce=[guid]::NewGuid().ToString('N');$log=Join-Path $PSScriptRoot ($nonce+'.log');$exe=Join-Path $PSScriptRoot 'Visibility.exe'
function Invoke-Visibility([string]$mode,[int]$preference){
 $args=@($mode,[string]$s.TargetPid,[string]$s.TargetBorn,[string]$s.ChildPid,[string]$s.ChildBorn,$s.ChildPath,$guid.ToString('B'),$log,[string]$preference)
 if(Test-Path $log){Remove-Item -LiteralPath $log}
 $argumentLine=($args|ForEach-Object{'"'+$_.Replace('"','\"')+'"'}) -join ' '
 if($mode -eq '--set'){
  Import-Module (Join-Path $PSHOME 'Modules\Appx\Appx.psd1') -ErrorAction Stop
  Invoke-CommandInDesktopPackage -PackageFamilyName 'windows.immersivecontrolpanel_cw5n1h2txyewy' -AppId 'microsoft.windows.immersivecontrolpanel' -Command $exe -Args $argumentLine -PreventBreakaway
  $deadline=[datetime]::UtcNow.AddSeconds(12);$completed=$false
  while([datetime]::UtcNow -lt $deadline){if(Test-Path $log){$text=Get-Content $log -Raw;if($text -match 'Result=([0-9a-fA-F]{8})'){$completed=$true;if($matches[1] -ne '00000000'){throw ('Genuine SetPreference failed: '+$text)};break}};Start-Sleep -Milliseconds 100}
  if(!$completed){throw 'Own packaged visibility helper did not finish within deadline'}
 }else{
  $psi=New-Object Diagnostics.ProcessStartInfo;$psi.FileName=$exe;$psi.Arguments=$argumentLine;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$process=[Diagnostics.Process]::Start($psi)
  try{if(!$process.WaitForExit(12000)){$process.Kill();$process.WaitForExit(2000)|Out-Null;throw 'Own visibility helper timed out'};if($process.ExitCode -ne 0){throw ('Visibility API failed '+$process.ExitCode+'; '+$log)}}finally{$process.Dispose()}
 }
 Get-Content $log -Raw
}
$read=Invoke-Visibility '--read' 0
$match=[regex]::Match($read,'Preference=(\d+)');if(!$match.Success){throw 'Preference not returned'};$old=[int]$match.Groups[1].Value
$backup=Join-Path $PSScriptRoot ('backup-'+$guid.ToString('N')+'.json')
if($Action -eq 'Read'){Write-Output $read;return}
if($Action -eq 'Promote'){
 if(!(Test-Path $backup)){[pscustomobject]@{Guid=$guid.ToString();ChildPath=$s.ChildPath;OriginalPreference=$old;CreatedUtc=[datetime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $backup -Encoding UTF8}
 Invoke-Visibility '--set' 2
}else{
 $b=Get-Content $backup -Raw|ConvertFrom-Json
 if($b.Guid -ne $guid.ToString() -or $b.ChildPath -ne $s.ChildPath){throw 'Backup identity mismatch'}
 if($old -eq [int]$b.OriginalPreference){Write-Output 'Original network preference already restored.';return}
 if($old -ne 2){throw 'Preference changed externally; refusing overwrite'}
 Invoke-Visibility '--set' ([int]$b.OriginalPreference)
}
