from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parent.parent
base=root/'outputs/Windows10-Components'
backup=base/'Lab/SettingsContentCompat/integration-backup'
backup.mkdir(exist_ok=True)
def edit(relative,pairs):
    p=base/relative;s=p.read_text(encoding='utf-8-sig')
    dest=backup/relative;dest.parent.mkdir(parents=True,exist_ok=True)
    if not dest.exists():dest.write_bytes(p.read_bytes())
    for before,after in pairs:
        assert s.count(before)==1,(relative,before,s.count(before))
        s=s.replace(before,after)
    p.write_text(s,encoding='utf-8-sig' if p.suffix=='.ps1' else 'utf8')
edit('Lab/SettingsSessionCompat/Enable-Settings10-VFS.ps1',[
 ('[switch]$WithoutNavigationCompat)','[switch]$WithoutNavigationCompat,[switch]$WithoutContentCompat)'),
 ("}else{Join-Path $base 'Lab\\SettingsCaptionCompat\\SettingsCaptionCompat.dll'}","}elseif($WithoutContentCompat){Join-Path $base 'Lab\\SettingsCaptionCompat\\SettingsCaptionCompat.dll'}else{Join-Path $base 'Lab\\SettingsContentCompat\\SettingsContentCompat.dll'}"),
 ('NavigationCompat=(!$WithoutNavigationCompat);','NavigationCompat=(!$WithoutNavigationCompat);ContentCompat=(!$WithoutNavigationCompat -and !$WithoutContentCompat);')])
edit('Enable-Settings10-VFS.ps1',[
 ('[switch]$WithoutNavigationCompat)','[switch]$WithoutNavigationCompat,[switch]$WithoutContentCompat)'),
 ('-WithoutNavigationCompat:$WithoutNavigationCompat','-WithoutNavigationCompat:$WithoutNavigationCompat -WithoutContentCompat:$WithoutContentCompat')])
edit('Start-Windows10-Maximum.ps1',[("if(!$s.NavigationCompat -or $s.Bootstrap -ine (Join-Path $PSScriptRoot 'Lab\\SettingsCaptionCompat\\SettingsCaptionCompat.dll')", "if(!$s.NavigationCompat -or !$s.ContentCompat -or $s.Bootstrap -ine (Join-Path $PSScriptRoot 'Lab\\SettingsContentCompat\\SettingsContentCompat.dll')")])
insert="""
content=base/'Lab/SettingsContentCompat'
content_manifest=json.loads((content/'manifest.json').read_text(encoding='utf-8-sig'))
for record in content_manifest['Files']+content_manifest['Dependencies']:
 p=Path(record['Path']);assert hashlib.sha256(p.read_bytes()).hexdigest()==record['SHA256'];files.append(p)
text_adapter=base/'Lab/SettingsControlTextCompat'
text_manifest=json.loads((text_adapter/'manifest.json').read_text(encoding='utf-8-sig'))
for name in ['SettingsControlTextCompat.c','DescriptionCallsite.h','SettingsControlTextCompat.dll']:
 p=text_adapter/name;assert hashlib.sha256(p.read_bytes()).hexdigest()==text_manifest['files'][name];files.append(p)
for path,digest in text_manifest['dependencies'].items():
 p=Path(path);assert hashlib.sha256(p.read_bytes()).hexdigest()==digest;files.append(p)
power=base/'Lab/SettingsPowerCompat'
power_manifest=json.loads((power/'adapter-manifest.json').read_text(encoding='utf-8-sig'))
for p,digest in [(power/'SettingsPowerCompat.c',power_manifest['sourceSHA256']),(power/'SettingsPowerCompat.dll',power_manifest['helperSHA256']),(Path(power_manifest['oldProviderPath']),power_manifest['oldProviderHash'])]:
 assert hashlib.sha256(p.read_bytes()).hexdigest()==digest;files.append(p)
files += [content/'manifest.json',text_adapter/'manifest.json',power/'adapter-manifest.json']
"""
edit('Lab/SettingsSessionCompat/Build.py',[("files=list(dict.fromkeys(files))",insert+"\nfiles=list(dict.fromkeys(files))")])
edit('Windows10-OneClick.ps1',[
 ("Version='oneclick-01'","Version='oneclick-02'"),
 ("'Lab\\SettingsCaptionCompat\\SettingsCaptionCompat.dll',","'Lab\\SettingsCaptionCompat\\SettingsCaptionCompat.dll','Lab\\SettingsContentCompat\\SettingsContentCompat.dll','Lab\\NetworkTrayCompat\\Ensure-NetworkTray.ps1','Lab\\NetworkTrayCompat\\NetworkTrayHost.exe',"),
 ("  Run-Stage 'Square window corners'", """  Run-Stage 'Windows 10 network tray handler' {
   if(!$report.MaximumState){throw 'Exact shell readiness record is missing.'}
   $shell=(Get-Content -LiteralPath $report.MaximumState -Raw -Encoding UTF8|ConvertFrom-Json).Explorer
   if(!$shell){throw 'Exact Explorer identity is missing.'}
   & (Join-Path $ComponentRoot 'Lab\\NetworkTrayCompat\\Ensure-NetworkTray.ps1') -TargetPid $shell.Pid -TargetBorn ([uint64]$shell.BirthFileTime) -Seconds $Seconds
  }
  Run-Stage 'Square window corners'"""),
 ("  Run-Stage 'Restore original window corners'","  Run-Stage 'Stop owned network tray handler' {& (Join-Path $ComponentRoot 'Lab\\NetworkTrayCompat\\Stop-NetworkTray.ps1')}\n  Run-Stage 'Restore original window corners'")])
print('Updated Settings content bootstrap and one-click network stage; no activation.')
