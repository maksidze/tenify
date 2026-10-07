$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lifecycle.ps1')
$path=New-DirectStartup -Seconds 5;$lease=Open-DirectStartup $path
try{
 Assert-DirectStartup $lease
 if(Test-Path -LiteralPath ($path+'.pending')){throw 'Startup publication left a temporary record.'}
 $saved=Read-DirectSharedJson $path
 if([long]$saved.Parent.Birth -ne [long]$lease.Parent.Birth){throw 'Published parent birth mismatch.'}
 Cancel-DirectStartup $lease 'Own publication test'
 $action=Join-Path $lease.State.Directory 'must-not-exist';$refused=$false
 try{Invoke-DirectStartupTransition $lease {[IO.File]::WriteAllText($action,'BAD')}}catch{$refused=$true}
 if(!$refused -or (Test-Path -LiteralPath $action)){throw 'Cancelled published transaction executed action.'}
 @{Passed=$true;AtomicPublished=$true;Birth=[string]$lease.Parent.Birth;CancelledActionRefused=$true}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'publication-own-proof.json') -Encoding UTF8
}finally{[IO.File]::WriteAllText($lease.State.TerminalFile,'Own publication fixture finished');$lease.Parent.Dispose()}
