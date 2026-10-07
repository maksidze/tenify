# Shared strict record validation. No process termination.
function Read-OwnedNetworkState([string]$Record){
 $lab=[IO.Path]::GetFullPath($PSScriptRoot)
 if(!$Record){$pointer=Join-Path $lab 'active-network-session.txt';if(!(Test-Path -LiteralPath $pointer)){return $null};$Record=[IO.File]::ReadAllText($pointer).Trim()}
 $recordPath=[IO.Path]::GetFullPath($Record)
 if([IO.Path]::GetDirectoryName($recordPath) -ne $lab -or [IO.Path]::GetFileName($recordPath) -notmatch '^run-[0-9a-f]{32}\.json$'){throw 'Network record is outside owned directory.'}
 $state=[IO.File]::ReadAllText($recordPath)|ConvertFrom-Json
 if($state.Mode -ne 'UntilStop'){throw 'Persistent network mode required.'}
 $stem=$recordPath.Substring(0,$recordPath.Length-5)
 if($state.ChildPath -ne (Join-Path $lab 'NetworkTrayUntilStop.exe') -or $state.StopFile -ne ($stem+'.stop') -or $state.Ready -ne ($stem+'.ready')){throw 'Network record paths differ.'}
 $process=$null
 try{$process=[Diagnostics.Process]::GetProcessById([int]$state.ChildPid);$handle=$process.Handle
  if([uint64]$process.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [uint64]$state.ChildBorn -or $process.MainModule.FileName -ne $state.ChildPath){$process.Dispose();$process=$null;throw 'Network helper identity differs; refuse reused PID.'}
 }catch [ArgumentException]{$process=$null}
 return [pscustomobject]@{Record=$recordPath;State=$state;Process=$process;Ready=([IO.File]::Exists($state.Ready));StopRequested=([IO.File]::Exists($state.StopFile))}
}
