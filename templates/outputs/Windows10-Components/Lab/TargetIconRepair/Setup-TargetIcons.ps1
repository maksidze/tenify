param([switch]$SkipThumbnail)
& (Join-Path $PSScriptRoot 'TargetIcons.ps1') -Action Setup -SkipThumbnail:$SkipThumbnail
