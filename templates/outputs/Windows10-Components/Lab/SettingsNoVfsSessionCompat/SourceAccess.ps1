param([Parameter(Mandatory=$true)][string]$Receipt,[switch]$Restore)
$ErrorActionPreference='Stop'
Import-Module "$PSHOME\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1"
Import-Module "$PSHOME\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1"
Import-Module "$PSHOME\Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1"
$base=[IO.Path]::GetFullPath((Split-Path (Split-Path $PSScriptRoot)))
$source=Get-Content (Join-Path $PSScriptRoot 'source-paths.json') -Raw|ConvertFrom-Json
$allowed=@{};foreach($e in $source.Files){$allowed[[IO.Path]::GetFullPath($e.Path).ToLowerInvariant()]=$e.SHA256}
function Check-Source([string]$path){
 $full=[IO.Path]::GetFullPath($path)
 if(!$full.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase) -or !$allowed.ContainsKey($full.ToLowerInvariant())){throw ('Not an exact pinned private source '+$path)}
 if((Get-Item -LiteralPath $full).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Source reparse file refused'}
 if((Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant() -ne $allowed[$full.ToLowerInvariant()]){throw ('Source hash differs '+$path)}
}
function Save-Journal($entries){$tmp=$Receipt+'.pending';[IO.File]::WriteAllText($tmp,(@($entries)|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false));if(Test-Path -LiteralPath $Receipt){$saved=$false;for($attempt=0;$attempt -lt 40;$attempt++){try{[IO.File]::Replace($tmp,$Receipt,$Receipt+'.previous');$saved=$true;break}catch{$io=$_.Exception -is [IO.IOException] -or $_.Exception.InnerException -is [IO.IOException];if(!$io -or $attempt -eq 39 -or !(Test-Path -LiteralPath $tmp)){throw};Start-Sleep -Milliseconds 50}};if(!$saved){throw 'Atomic ACL journal write failed'}}else{[IO.File]::Move($tmp,$Receipt)}}
if($Restore){
 $entries=@(Get-Content $Receipt -Raw|ConvertFrom-Json)
 foreach($e in $entries){Check-Source $e.Path;$acl=Get-Acl -LiteralPath $e.Path;if($acl.Sddl -eq $e.PlannedAfter -or ($e.After -and $acl.Sddl -eq $e.After)){$acl.SetSecurityDescriptorSddlForm($e.Before);Set-Acl -LiteralPath $e.Path -AclObject $acl}elseif($acl.Sddl -ne $e.Before){throw ('Foreign ACL change preserved '+$e.Path)}}
 return
}
if(Test-Path -LiteralPath $Receipt){throw 'Immutable source ACL receipt already exists'}
$sid=[Security.Principal.SecurityIdentifier]::new('S-1-15-2-2376884767-3641813526-1736181949-1293975252-228260496-2789807194-3363476418')
$entries=@()
foreach($item in $source.Files){
 Check-Source $item.Path;$acl=Get-Acl -LiteralPath $item.Path;$before=$acl.Sddl
 $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::ReadAndExecute,[Security.AccessControl.AccessControlType]::Allow);$acl.AddAccessRule($rule)
 $e=@{Path=$item.Path;Before=$before;PlannedAfter=$acl.Sddl;After=$null};$entries+=,$e
 Save-Journal $entries
 Set-Acl -LiteralPath $item.Path -AclObject $acl;$e.After=(Get-Acl -LiteralPath $item.Path).Sddl;Save-Journal $entries
}

