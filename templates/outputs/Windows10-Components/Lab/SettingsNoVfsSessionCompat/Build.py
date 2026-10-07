from pathlib import Path
import subprocess,hashlib,json,sys
L=Path(__file__).resolve().parent;R=L.parents[3];Z=R/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
def cc(src,out,libs):
 p=subprocess.run([str(Z),'cc','-target','x86_64-windows-gnu','-municode','-O2','-Wl,--subsystem,windows',str(L/src),'-o',str(L/out),*libs],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=60)
 (L/(out+'.build.log')).write_bytes(p.stdout+p.stderr)
 if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
cc('SessionEntry.c','SettingsNoVfsEntry.exe',['-lshell32','-lbcrypt','-lpsapi'])
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
H=L.parent/'SettingsNoVfsCompat';m=json.loads((H/'adapter-metadata.json').read_text());m['SelectorSHA256']=sha(m['Selector']);m['Files']=[dict(Path=x['Path'],SHA256=sha(x['Path'])) for x in m['Files']];(H/'adapter-metadata.json').write_text(json.dumps(m,indent=2))
files=[p for p in L.iterdir() if p.suffix in ['.py','.exe','.c','.h','.ps1'] and p.is_file()]
files += [Path(x['Path']) for x in m['Files']]+[H/'adapter-metadata.json']
for folder in ['SettingsContentCompat','SettingsCaptionCompat','SettingsControlTextCompat','SettingsPowerCompat','SettingsSystemProfileCompat']:
 d=L.parent/folder
 if d.exists():files += list(d.glob('*.dll'))
files += [H/'Launch-SettingsNoVfs.py',L.parent/'NativeHostPCSCompat/Launch-NativeDcomp.py',L.parents[1]/'Launch-TouchpadCompat.py']
files += list((L.parents[1]/'Image/4/Windows/ImmersiveControlPanel').glob('*.dll'))
sources=[]
for folder in ['SettingsNoVfsCompat','SettingsNoVfsDiagnostics','SettingsNoVfsXamlCompat','SettingsContentCompat','SettingsCaptionCompat','SettingsControlTextCompat','SettingsPowerCompat','SettingsSystemProfileCompat']:sources+=list((L.parent/folder).glob('*.dll'))
for folder in ['Image/4/Windows/ImmersiveControlPanel','Image/4/Windows/SystemResources/Windows.UI.SettingsAppThreshold']:sources += [p for p in (L.parents[1]/folder).rglob('*') if p.is_file()]
(L/'source-paths.json').write_text(json.dumps(dict(Files=[dict(Path=str(p),SHA256=sha(p)) for p in sorted(set(sources))]),indent=2))
files += [L/'source-paths.json']
manifest=dict(NoVFS=True,ActualRuntimeRepeat=True,ActualVisualUIConfirmed=False,DefaultProfile='SettingsNoVfsXamlCompat',Files=[dict(Path=str(p),SHA256=sha(p)) for p in sorted(set(files))])
(L/'manifest.json').write_text(json.dumps(manifest,indent=2))
