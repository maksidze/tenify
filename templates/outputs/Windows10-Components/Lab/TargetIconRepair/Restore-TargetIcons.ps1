param([string]$Journal)
& (Join-Path $PSScriptRoot 'TargetIcons.ps1') -Action Restore -Journal $Journal
