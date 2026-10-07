param([string]$PackageSid='S-1-15-2-515815643-2845804217-1874292103-218650560-777617685-4287762684-137415000',[switch]$Restore)
$ErrorActionPreference='Stop'
foreach($name in 'Security','Management','Utility'){Import-Module (Join-Path $PSHOME ('Modules/Microsoft.PowerShell.'+$name+'/Microsoft.PowerShell.'+$name+'.psd1'))}
if($PackageSid -notlike 'S-1-15-2-*'){throw 'An AppContainer package SID is required'}
$receipt=Join-Path $PSScriptRoot 'start-access-receipt.json'
$base=[IO.Path]::GetFullPath($PSScriptRoot)
function Save-Receipt($entries){$tmp=$receipt+'.pending';[IO.File]::WriteAllText($tmp,(ConvertTo-Json -InputObject @($entries) -Depth 6),[Text.UTF8Encoding]::new($false));if(Test-Path -LiteralPath $receipt){$saved=$false;for($attempt=0;$attempt -lt 40;$attempt++){try{[IO.File]::Replace($tmp,$receipt,$receipt+'.previous');$saved=$true;break}catch{$io=$_.Exception -is [IO.IOException] -or $_.Exception.InnerException -is [IO.IOException];if(!$io -or $attempt -eq 39 -or !(Test-Path -LiteralPath $tmp)){throw};Start-Sleep -Milliseconds 50}};if(!$saved){throw 'Atomic ACL journal write failed'}}else{[IO.File]::Move($tmp,$receipt)}}
function Check-Path($path){$full=[IO.Path]::GetFullPath($path);if($full -ine $base -and !$full.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Start access path escaped its private directory'};if((Get-Item -LiteralPath $full).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Start source reparse point refused'}}
$entries=@();if(Test-Path -LiteralPath $receipt){$entries=@(Get-Content -LiteralPath $receipt -Raw -Encoding UTF8|ConvertFrom-Json)}
if($Restore){foreach($entry in $entries){Check-Path $entry.Path;$acl=Get-Acl -LiteralPath $entry.Path;if($acl.Sddl -eq $entry.After -or $acl.Sddl -eq $entry.PlannedAfter){$acl.SetSecurityDescriptorSddlForm($entry.Before);Set-Acl -LiteralPath $entry.Path -AclObject $acl}elseif($acl.Sddl -ne $entry.Before){throw 'Foreign Start source ACL change preserved'}};return}
$paths=@($base)+@('wincorlib.dll','WinCorHost.dll','StartUI_.dll','StartCompat.ini'|ForEach-Object {Join-Path $base $_})
$resources=Join-Path $base 'Resources';if(Test-Path -LiteralPath $resources){$paths+=@($resources)+@(Get-ChildItem -LiteralPath $resources -Recurse|ForEach-Object {$_.FullName})}
$sid=[Security.Principal.SecurityIdentifier]::new($PackageSid)
foreach($path in $paths){
 Check-Path $path;$acl=Get-Acl -LiteralPath $path;$existing=@($entries|Where-Object Path -eq $path)
 if($existing){if($acl.Sddl -ne $existing[0].Before -and $acl.Sddl -ne $existing[0].After -and $acl.Sddl -ne $existing[0].PlannedAfter){throw 'Foreign Start source ACL change preserved'};if($acl.Sddl -eq $existing[0].After){continue}}
 $before=$acl.Sddl;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::ReadAndExecute,[Security.AccessControl.AccessControlType]::Allow))
 if($existing){$entry=$existing[0];$entry.PlannedAfter=$acl.Sddl}else{$entry=[pscustomobject]@{Path=$path;Before=$before;PlannedAfter=$acl.Sddl;After=$null};$entries+=,$entry}
 Save-Receipt $entries
 Set-Acl -LiteralPath $path -AclObject $acl;$entry.After=(Get-Acl -LiteralPath $path).Sddl;Save-Receipt $entries
}
Write-Output 'Private Start files are readable by the Start AppContainer; receipt saved'
