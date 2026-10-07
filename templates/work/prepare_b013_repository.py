"""Maintainer-only export of authored b013 sources; never copies Windows binaries."""
from pathlib import Path
import json, csv, hashlib, re, shutil

ROOT=Path(__file__).resolve().parent.parent
BASE=ROOT/'outputs/Windows10-Components'
REPO=ROOT/'Windows10-b013'
PREFIX='outputs/Windows10-Components/'
FOLDERS='''NoVfsShellCompat NativeHostPCSCompat NativeWinXCompat NativeMenuSquareV2 NativeThemeMenuBootstrap NativeThemeMenuCompat IconRoutesNoVfsCompat IconResourceMaximum FolderIconCompat TargetIconRepair HybridThemeBootstrap ThemeFolderHybridCompat InputSwitchCompat XamlQuirkCompat ClassicContextMenuCompat ResourceCompat DisplayMonitorPublisher WindowStyleSession ElevatedCornersCompat SnapHoverCompat DirectLaunchLifecycle BrokerGuiEntry SettingsContentCompat SettingsCaptionCompat SettingsControlTextCompat SettingsPowerCompat SettingsSystemProfileCompat SettingsNoVfsCompat SettingsNoVfsXamlCompat SettingsNoVfsSessionCompat StartCompat StartSessionCompat NetworkTrayCompat NetworkTrayUntilStopCompat NetworkTrayVisibilityCompat ControlThemeBootstrap Theme10BrowserProbe HostMultitaskingCompat WindowGroupCompat AppControlTheme10Compat'''.split()
SOURCE_EXT={'.py','.ps1','.c','.cpp','.h','.hpp','.cs','.def','.bat'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return p.relative_to(ROOT).as_posix()
def normalize(s):
    for old,new in [(str(ROOT),'@WORKSPACE@'),(str(ROOT).replace('\\','/'),'@WORKSPACE@'),(str(ROOT).replace('\\','\\\\'),'@WORKSPACE_ESC@'),('@PYTHON_DIR_ESC@','@PYTHON_DIR@'),('@PYTHON_DIR@','@PYTHON_DIR@'),('C:\\\\Users\\\\MAKSIDZE\\\\.cache\\\\codex-runtimes\\\\codex-primary-runtime\\\\dependencies\\\\python','@PYTHON_DIR_ESC@')]:
        s=s.replace(old,new)
    return s
sources=set(); jsons=set(); declared=set(); windows={}
for folder in FOLDERS:
    d=BASE/'Lab'/folder
    for p in d.glob('*'):
        if p.is_file() and p.suffix.lower() in SOURCE_EXT:sources.add(p)
        if p.is_file() and p.suffix.lower()=='.json' and p.stat().st_size<2_000_000:
            if not any(x in p.name.lower() for x in ['live','trial','diagnostic','snapshot','state','vfs-','trace','abi','qi-','caller','visibility','before','after','compiler','run-']):jsons.add(p)
    # Static authored headers in nested resource-route folder, not owned runs.
    for p in d.glob('ResourceRoutesNoVfs/*'):
        if p.suffix.lower() in SOURCE_EXT:sources.add(p)
for p in BASE.glob('*'):
    if p.is_file() and p.suffix.lower() in SOURCE_EXT and not any(x in p.name for x in ['VFS','USVFS']):sources.add(p)
for p in (BASE/'WindowStyle').glob('*.ps1'):sources.add(p)
for p in ROOT.glob('*.bat'):sources.add(p)
for p in (ROOT/'work').glob('*.py'):
    # Only supporting authored modules; no decompiled/disassembly or vendor sources.
    if p.stat().st_size<150_000:sources.add(p)

def walk(x):
    if isinstance(x,dict):
        for k,v in x.items():
            if k in ('Path','path','Source','Destination','Old','Host','Private','Helper','Selector','NativeModule','Fixture','BridgeTemplate','Python','NativePath','PDB') and isinstance(v,str):
                p=Path(v)
                if p.is_file():
                    if p.is_relative_to(ROOT):declared.add(p)
                    elif str(p).lower().startswith('c:\\windows\\'):windows[str(p)]=sha(p)
            walk(v)
    elif isinstance(x,list):
        for v in x:walk(v)
for p in sorted(jsons):
    try:walk(json.loads(p.read_text(encoding='utf-8-sig')))
    except (ValueError,UnicodeError):continue
for p in declared:
    if p.suffix.lower() in SOURCE_EXT|{'.ini','.txt'}:sources.add(p)
    elif p.suffix.lower()=='.json':jsons.add(p)
sources |= jsons
templates=[]
for p in sorted(sources):
    if any(x in p.parts for x in ['sessions','runs','__pycache__','fixtures']):continue
    try:s=p.read_text(encoding='utf-8-sig')
    except UnicodeError:
        try:s=p.read_text(encoding='utf-16')
        except UnicodeError:continue
    target=REPO/'templates'/rel(p);target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(normalize(s),encoding='utf-8')
    templates.append(dict(Path=rel(p),OriginalSHA256=sha(p),Encoding='utf-8'))
files=list(csv.DictReader((BASE/'Metadata/files.csv').open(encoding='utf-8-sig')))
media_by_sha={f['sha256']:f['path'].replace('\\','/') for f in files}
image_requests={}
for p in declared:
    if p.is_relative_to(BASE/'Image/4'):
        image_requests[p.relative_to(BASE/'Image/4').as_posix()]=sha(p)
for folder in ['Windows/ImmersiveControlPanel','Windows/SystemResources/Windows.UI.SettingsAppThreshold','Windows/SystemResources/Windows.UI.ShellCommon']:
    for p in (BASE/'Image/4'/folder).rglob('*'):
        if p.is_file():image_requests[p.relative_to(BASE/'Image/4').as_posix()]=sha(p)
for f in ['Windows/explorer.exe','Windows/ru-RU/explorer.exe.mui','Windows/Resources/Themes/aero/aero.msstyles']:
    p=BASE/'Image/4'/f;image_requests[f]=sha(p)
out=REPO/'packaging';out.mkdir(parents=True,exist_ok=True)
(out/'template-files.json').write_text(json.dumps(templates,indent=2),encoding='utf-8')
(out/'media-files.json').write_text(json.dumps(image_requests,indent=2),encoding='utf-8')
(out/'host-files.json').write_text(json.dumps({k.removeprefix('C:\\Windows\\').replace('\\','/'):v for k,v in sorted(windows.items())},indent=2),encoding='utf-8')
(out/'declared-artifacts.local.json').write_text(json.dumps([rel(p) for p in sorted(declared) if not p.is_relative_to(BASE/'Image')],indent=2),encoding='utf-8')
print(json.dumps(dict(Templates=len(templates),ImageFiles=len(image_requests),HostFiles=len(windows),Declared=len(declared))))
