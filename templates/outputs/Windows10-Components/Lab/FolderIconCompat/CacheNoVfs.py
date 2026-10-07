"""Disposable own private-desktop icon/cache proof. No USVFS is loaded."""
from pathlib import Path
import ctypes as C, ctypes.wintypes as W, json,hashlib,os,subprocess,uuid,shutil
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1];ROOT=LAB.parents[3]
PY=Path(__import__('sys').executable)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'work/compat-research/zig-cache')
zig=ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
def build(args,name):
 p=subprocess.run([str(zig)]+args,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=90,env=env)
 (LAB/name).write_text(p.stdout+p.stderr)
 if p.returncode:raise RuntimeError(p.stderr)
exe=LAB/'FolderCacheProbe.exe'
build(['c++','-target','x86_64-windows-gnu','-O2','-std=c++17','-municode','-Wl,--subsystem,windows',str(LAB/'FolderCacheProbe.cpp'),'-o',str(exe),'-lole32','-luuid','-lshell32','-luser32','-lgdi32'],'cache-build.txt')
routeLab=LAB/'ResourceRoutesNoVfs';routeLab.mkdir(exist_ok=True)
original=BASE/'Lab/IconResourceMaximum';source=(original/'IconRoutes.c').read_text().replace('../SettingsContentCompat/HashCheck.h','../../SettingsContentCompat/HashCheck.h')
source=source.replace('H(L"kernel32.dll",GetProcAddress)};', 'H(L"kernel32.dll",GetProcAddress),'+','.join('H(L"kernelbase.dll",'+name+')' for name in ['FindResourceW','FindResourceA','FindResourceExW','FindResourceExA','LoadResource','SizeofResource','LoadLibraryW','LoadLibraryExW','GetProcAddress'])+'};')
source=source.replace('if(*slot!=hooks[h].original)break;','if(*slot!=hooks[h].original)continue;')
source=source.replace('if(module==self)return TRUE;','if(module==self||module==GetModuleHandleW(L"kernel32.dll")||module==GetModuleHandleW(L"kernelbase.dll")||module==GetModuleHandleW(L"ntdll.dll"))return TRUE;')
source+='\n#include "CacheKeyPins.h"\n#include "CacheKey.h"\n'
(routeLab/'IconRoutes.c').write_text(source)
records=json.loads((original/'manifest.json').read_text())['Records'];routes={};missing=[];pairProof=[]
resourceNs={'__file__':str(original/'Build.py')};exec((original/'Build.py').read_text().split('inventory=json.loads')[0],resourceNs)
readResources=resourceNs['resources'];serialize=resourceNs['serialize']
storage=Path('C:/Windows/System32/windows.storage.dll');pe=resourceNs['pefile'].PE(str(storage));code=pe.get_data(0x257930,32)
(routeLab/'CacheKeyPins.h').write_text('#define STORAGE_SHA '+json.dumps(sha(storage))+'\nstatic const unsigned char locationBytes[]={'+','.join(str(x)for x in code)+'};\n')
for r in records:
 assert sha(r['Host'])==r['HostSHA256'] and sha(r['Private'])==r['PrivateSHA256']
 host=Path(r['Host']);private=Path(r['Private']);routes[str(host).lower()]=(host,private)
 if r['Mode']=='DataOnlyMUNVFS':
  name=host.name[:-4];paired=Path('C:/Windows/System32')/name
  if not paired.exists():paired=Path('C:/Windows')/name
  if paired.exists():
   # Preserve paired DLL's own non-icon resources as well as MUN resources.
   # The container stays data-only; no executable code is mapped from it.
   try:own=readResources(paired)
   except (KeyError,IndexError,AttributeError):own={}
   merged=readResources(private);combined=dict(merged);preserved={key:value for key,value in own.items()if key[0]not in (3,14)}
   collision=sum(key in merged and merged[key]!=value for key,value in preserved.items())
   combined.update(preserved)
   absentIcons={key:value for key,value in own.items()if key[0]in (3,14)and key not in merged};combined.update(absentIcons)
   pairedPrivate=routeLab/'PairedContainers'/(paired.name+'.mun')
   serialize(private,pairedPrivate,combined)
   actual=readResources(pairedPrivate);assert all(actual[key]==value for key,value in preserved.items())
   assert all(actual[key]==value for key,value in merged.items()if key[0]in(3,14))
   pairProof.append(dict(Host=str(paired),Container=str(pairedPrivate),NativeNonIconResourcesPreserved=len(preserved),NativeNonIconCollisions=collision,AllMergedIconResourcesPreserved=True))
   routes[str(paired).lower()]=(paired,pairedPrivate)
  else:missing.append(name)
def wide(p):return 'L'+json.dumps(str(p))
header=['#define ROUTE_COUNT '+str(len(routes)), 'typedef struct {PCWSTR host,privatePath;const char *hostSha,*privateSha;} ROUTE;', 'static ROUTE routes[]={']
dependencies={};routeRecords=[]
for host,private in routes.values():
 h,p=sha(host),sha(private);dependencies[str(host)]=h;dependencies[str(private)]=p
 header.append('{'+','.join([wide(host),wide(private),json.dumps(h),json.dumps(p)])+'},')
 routeRecords.append(dict(Host=str(host),Private=str(private),HostSHA=h,PrivateSHA=p))
header+=['};','#define FIXTURE_PATH '+wide(exe),'#define FIXTURE_SHA '+json.dumps(sha(exe)),'#define EXPLORER_PATH '+wide(BASE/'Runtime/Explorer10/explorer.exe'),'#define EXPLORER_SHA '+json.dumps(sha(BASE/'Runtime/Explorer10/explorer.exe'))]
(routeLab/'Routes.h').write_text('\n'.join(header))
dll=routeLab/'IconRoutes.NoVfs.Fixture.dll'
build(['cc','-target','x86_64-windows-gnu','-O2','-shared',str(routeLab/'IconRoutes.c'),'-o',str(dll),'-lbcrypt','-lpsapi','-lshell32','-luser32'],'routes-build.txt')
(routeLab/'fixture-manifest.json').write_text(json.dumps(dict(Scope='Experimental disposable own process; not production; no USVFS',DLLSHA=sha(dll),FixtureSHA=sha(exe),Routes=routeRecords,MissingModulePairs=missing,PairedResourceProof=pairProof,Dependencies=dependencies),indent=2))
class SI(C.Structure):_fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('reserved2',W.WORD),('reservedPtr',C.c_void_p),('stdin',W.HANDLE),('stdout',W.HANDLE),('stderr',W.HANDLE)]
class PI(C.Structure):_fields_=[('process',W.HANDLE),('thread',W.HANDLE),('pid',W.DWORD),('tid',W.DWORD)]
k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32',use_last_error=True);papi=C.WinDLL('psapi',use_last_error=True)
def api(d,n,r,a):f=getattr(d,n);f.restype=r;f.argtypes=a;return f
create=api(k,'CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,C.c_void_p,C.c_void_p,W.BOOL,W.DWORD,C.c_void_p,W.LPCWSTR,C.POINTER(SI),C.POINTER(PI)])
close=api(k,'CloseHandle',W.BOOL,[W.HANDLE]);wait=api(k,'WaitForSingleObject',W.DWORD,[W.HANDLE,W.DWORD]);term=api(k,'TerminateProcess',W.BOOL,[W.HANDLE,W.UINT]);exitCode=api(k,'GetExitCodeProcess',W.BOOL,[W.HANDLE,C.POINTER(W.DWORD)])
desktopCreate=api(u,'CreateDesktopW',W.HANDLE,[W.LPCWSTR,W.LPCWSTR,C.c_void_p,W.DWORD,W.DWORD,C.c_void_p]);desktopClose=api(u,'CloseDesktop',W.BOOL,[W.HANDLE])
setAttr=api(k,'SetFileAttributesW',W.BOOL,[W.LPCWSTR,W.DWORD]);enum=api(papi,'EnumProcessModules',W.BOOL,[W.HANDLE,C.POINTER(W.HMODULE),W.DWORD,C.POINTER(W.DWORD)]);moduleName=api(papi,'GetModuleFileNameExW',W.DWORD,[W.HANDLE,W.HMODULE,W.LPWSTR,W.DWORD])
nonce=uuid.uuid4().hex;directory=LAB/'cache-sessions'/nonce;directory.mkdir(parents=True)
empty=directory/'EmptyFolder';empty.mkdir();nonempty=directory/'NonemptyFolder';nonempty.mkdir();(nonempty/'one.txt').write_text('Own fixture');(nonempty/'two.txt').write_text('Own fixture')
custom=directory/'CustomFolder';custom.mkdir()
imageres=next(Path(r['Private']) for r in records if Path(r['Host']).name.lower()=='imageres.dll.mun')
(custom/'desktop.ini').write_text('[.ShellClassInfo]\r\nIconResource='+str(imageres)+',-3\r\n',encoding='utf-16')
assert setAttr(str(custom),1) and setAttr(str(custom/'desktop.ini'),6)
desktopName='OwnIconNoVfs_'+nonce;desk=desktopCreate(desktopName,None,None,0,0x1ff,None)
if not desk:raise C.WinError(C.get_last_error())
results=[]
try:
 for mode in ['native','no-vfs','no-vfs-key']:
  dest=directory/mode;dest.mkdir();si=SI();si.cb=C.sizeof(si);si.desktop='WinSta0\\'+desktopName;si.flags=1;si.show=0;pi=PI()
  cmd=subprocess.list2cmdline([str(exe),str(dest),str(empty),str(nonempty),str(BASE),'-' if mode=='native' else str(dll),str(custom),mode])
  try:
   if not create(str(exe),C.create_unicode_buffer(cmd),None,None,False,0x08000000,None,str(LAB),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
   observedModules=set()
   for attempt in range(500):
    if wait(pi.process,100)==0:break
    modules=(W.HMODULE*2048)();needed=W.DWORD()
    if enum(pi.process,modules,C.sizeof(modules),C.byref(needed)) and needed.value<=C.sizeof(modules):
     for m in modules[:needed.value//C.sizeof(W.HMODULE)]:
      text=C.create_unicode_buffer(32768)
      if moduleName(pi.process,m,text,len(text)):observedModules.add(text.value)
   killed=wait(pi.process,0)!=0
   if killed:term(pi.process,0xdec9);wait(pi.process,3000)
   code=W.DWORD();exitCode(pi.process,C.byref(code));report={}
   try:report=json.loads((dest/'icons.json').read_text())if (dest/'icons.json').exists()else{}
   except (ValueError,OSError) as e:report={'parseError':str(e)}
   for icon in report.get('icons',[]):
    file=dest/(icon['name']+'.bgra');icon['pixelsSHA']=sha(file)if file.exists()else None
   assert not any('usvfs' in m.lower() for m in observedModules)
   results.append(dict(mode=mode,pid=pi.pid,exit=code.value,killed=killed,directory=str(dest),modules=sorted(observedModules),report=report));print(mode,pi.pid,code.value,flush=True)
  finally:
   if pi.thread:close(pi.thread)
   if pi.process:close(pi.process)
finally:
 closed=desktopClose(desk)
proof=dict(Scope='Same own folder native then resource-only API route; own desktop.ini; own forced thumbnail only; no VFS/shared cache deletion/live manipulation',DesktopClosed=bool(closed),DLLSHA=sha(dll),FixtureSHA=sha(exe),Results=results)
(LAB/'cache-no-vfs-proof.json').write_text(json.dumps(proof,indent=2))
from PIL import Image,ImageDraw
names=list(dict.fromkeys(r['name'] for result in results for r in result['report'].get('icons',[])if r.get('drawn')))
im=Image.new('RGB',(len(results)*180+240,len(names)*115+35),'#dedede');draw=ImageDraw.Draw(im)
for col,result in enumerate(results):
 draw.text((250+col*180,3),result['mode'],fill='black');rows={r['name']:r for r in result['report'].get('icons',[])}
 for i,name in enumerate(names):
  draw.text((2,40+i*115),name,fill='black');r=rows.get(name,{});file=Path(result['directory'])/(name+'.bgra')
  if file.exists():
   icon=Image.frombytes('RGBA',(r['width'],r['height']),file.read_bytes(),'raw','BGRA');im.paste(icon,(250+col*180,28+i*115),icon if icon.getextrema()[3][1]>0 else None)
im.save(LAB/'cache-no-vfs-comparison.png')
