param([ValidateRange(15,86400)][int]$Seconds=3600,[switch]$UntilStop)
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'WindowCorners.ps1') -Mode Enable -Seconds $Seconds -UntilStop:$UntilStop
