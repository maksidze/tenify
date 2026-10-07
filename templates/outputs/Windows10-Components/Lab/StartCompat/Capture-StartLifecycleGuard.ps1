param([Parameter(Mandatory=$true)][string]$Prefix)
$ErrorActionPreference='Stop'
$state=Get-Content -LiteralPath ($Prefix+'.status.json') -Raw | ConvertFrom-Json
if($state.Session -notmatch '^StartCompatLifecycle_[a-f0-9]{10}$'){throw 'Unexpected trace session name.'}
$deadline=[DateTime]::Parse($state.DeadlineUtc).ToUniversalTime()
$expectedBirth=[DateTime]::Parse($state.HelperCreationUtc).ToUniversalTime()
[IO.File]::WriteAllText($Prefix+'.guard-ready',"PID=$PID")
while([DateTime]::UtcNow -lt $deadline){
 if(Test-Path -LiteralPath ($Prefix+'.finished')){return}
 $helper=Get-Process -Id $state.HelperPid -ErrorAction SilentlyContinue
 if(-not $helper -or $helper.StartTime.ToUniversalTime() -ne $expectedBirth){break}
 Start-Sleep -Milliseconds 250
}
# The name was generated for this exact owned session; never stop a foreign logger.
& logman.exe stop $state.Session -ets *> ($Prefix+'.guard-stop.log')
[IO.File]::WriteAllText($Prefix+'.guard-finished',[DateTime]::UtcNow.ToString('o'))
