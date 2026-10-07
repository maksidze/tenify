from pathlib import Path
root=Path(__file__).resolve().parent.parent
base=root/'outputs/Windows10-Components'
p=base/'Windows10-OneClick.ps1'
s=p.read_text(encoding='utf-8-sig')
s=s.replace("Version='oneclick-03'", "Version='oneclick-04'")
begin=s.index("  $iconManifest=Join-Path $ComponentRoot")
end=s.index("\n }\n if($Mode -eq 'Check')",begin)
s=s[:begin]+"""  & $python (Join-Path $ComponentRoot 'Validate-ShellExtensions.py')
  if($LASTEXITCODE -ne 0){throw 'Classic menu or Icons10Maximum dependency validation failed.'}"""+s[end:]
p.write_text(s,encoding='utf-8-sig')
