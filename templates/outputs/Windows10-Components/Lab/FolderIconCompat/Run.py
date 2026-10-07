from pathlib import Path
import sys,os,json,hashlib,subprocess,uuid,ctypes as C,ctypes.wintypes as W
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1];ROOT=LAB.parents[3]
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'work/compat-research/zig-cache')
zig=ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
p=subprocess.run([str(zig),'c++','-target','x86_64-windows-gnu','-O2','-std=c++17','-municode','-Wl,--subsystem,windows',str(LAB/'FolderProbe.cpp'),'-o',str(LAB/'FolderProbe.exe'),'-lole32','-luuid','-lshell32','-luser32','-lgdi32'],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,text=True,env=env,timeout=90)
(LAB/'build.txt').write_text(p.stdout+p.stderr)
if p.returncode:print(p.stderr);raise SystemExit(p.returncode)
sys.path.insert(0,str(BASE/'Lab/SettingsSessionCompat'));import SessionVFS
SessionVFS.LAB=LAB
(LAB/'private-usvfs-provenance.json').write_bytes((BASE/'Lab/SettingsSessionCompat/private-usvfs-provenance.json').read_bytes())
nonce=uuid.uuid4().hex;directory=LAB/'sessions'/nonce;directory.mkdir(parents=True)
state=dict(Nonce=nonce,Directory=str(directory),VfsProxy=str(directory/'PrivateUSVFS/usvfs_proxy_x64.exe'));state['Files']=SessionVFS.validate(state,True)
source=(BASE/'Probe-USVFS.py').read_text(encoding='utf-8-sig').split('\ntry:\n params=')[0]
source=source.replace("bin=base/'Tools/USVFS/bin'","bin=Path("+repr(str(directory/'PrivateUSVFS'))+")")
sys.argv=[str(BASE/'Probe-USVFS.py'),'--preset','selftest'];ns={'__file__':str(BASE/'Probe-USVFS.py')};exec(source,ns)
results=[];desk=None;connected=False;params=None
try:
 desktopName='OwnFolderIcons_'+nonce;desk=ns['desktopCreate'](desktopName,None,None,0,0x1ff,None)
 if not desk:raise C.WinError(C.get_last_error())
 records=json.loads((BASE/'Lab/IconResourceMaximum/manifest.json').read_text())['Records']
 for mode in ['native','merged','oldmun']:
  dest=directory/mode;dest.mkdir();empty=dest/'EmptyFolder';empty.mkdir();nonempty=dest/'NonemptyFolder';nonempty.mkdir();(nonempty/'one.txt').write_text('Own fixture');(nonempty/'two.txt').write_text('Own fixture')
  params=ns['parametersCreate']();ns['setName'](params,('OwnFolderIcons_'+uuid.uuid4().hex).encode());ns['setLog'](params,0);ns['setDebug'](params,False)
  if not ns['connect'](params):raise C.WinError(C.get_last_error())
  connected=True
  # Do not propagate resource mappings into shell/broker helpers outside this owned child.
  for name in ['dllhost.exe','explorer.exe','RuntimeBroker.exe','SearchHost.exe','ShellExperienceHost.exe','StartMenuExperienceHost.exe']:ns['blacklist'](name)
  if mode!='native':
   for r in records:
    if r['Mode']!='DataOnlyMUNVFS':continue
    path=Path(r['Private'] if mode=='merged' else r['Old']);pin=r['PrivateSHA256']if mode=='merged'else r['OldSHA256'];assert hashlib.sha256(path.read_bytes()).hexdigest()==pin
    if not ns['link'](str(path),r['Host'],0):raise C.WinError(C.get_last_error())
  si=ns['SI']();si.cb=C.sizeof(si);si.desktop='WinSta0\\'+desktopName;si.flags=1;si.show=0;pi=ns['PI']();exe=LAB/'FolderProbe.exe';command=subprocess.list2cmdline([str(exe),str(dest),str(empty),str(nonempty),str(BASE)])
  try:
   if not ns['create'](str(exe),C.create_unicode_buffer(command),None,None,False,0x08000000,None,str(LAB),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
   killed=ns['wait'](pi.process,50000)!=0
   if killed:ns['term'](pi.process,0xdec9);ns['wait'](pi.process,3000)
   code=W.DWORD();ns['exitCode'](pi.process,C.byref(code));report=json.loads((dest/'icons.json').read_text())if (dest/'icons.json').exists()else{}
   for icon in report.get('icons',[]):
    file=dest/(icon['name']+'.bgra');icon['pixelsSHA']=hashlib.sha256(file.read_bytes()).hexdigest()if file.exists()else None
   results.append(dict(mode=mode,pid=pi.pid,exit=code.value,killed=killed,directory=str(dest),report=report));print(mode,pi.pid,code.value)
  finally:
   if pi.thread:ns['close'](pi.thread)
   if pi.process:ns['close'](pi.process)
   ns['disconnect']();connected=False;ns['parametersFree'](params);params=None
finally:
 if connected:ns['disconnect']()
 if params:ns['parametersFree'](params)
 if desk:ns['desktopClose'](desk)
(LAB/'own-proof.json').write_text(json.dumps(dict(Scope='own hidden icon API children; no shared cache clearing, system file changes or live shell manipulation',Results=results),indent=2))
from PIL import Image,ImageDraw
names=[r['name']for r in results[0]['report'].get('icons',[])if r.get('drawn')]
im=Image.new('RGB',(len(results)*180+230,len(names)*115+35),'#dedede');draw=ImageDraw.Draw(im)
for k,result in enumerate(results):
 draw.text((240+k*180,3),result['mode'],fill='black');rows={r['name']:r for r in result['report'].get('icons',[])}
 for i,name in enumerate(names):
  draw.text((2,40+i*115),name,fill='black');r=rows.get(name,{});file=Path(result['directory'])/(name+'.bgra')
  if file.exists():
   icon=Image.frombytes('RGBA',(r['width'],r['height']),file.read_bytes(),'raw','BGRA');im.paste(icon,(240+k*180,28+i*115),icon if icon.getextrema()[3][1]>0 else None)
im.save(LAB/'comparison.png')
