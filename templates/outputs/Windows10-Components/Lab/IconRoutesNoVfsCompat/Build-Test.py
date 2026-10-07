from pathlib import Path
import sys,json,hashlib,subprocess,os,ctypes as C,ctypes.wintypes as W,uuid,shutil
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1];ROOT=LAB.parents[3];OWN=BASE/'Lab/FolderIconCompat';OLD=BASE/'Lab/IconResourceMaximum'
sys.path.insert(0,str(ROOT/'work/pylib'));import pefile
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def wide(p):return 'L'+json.dumps(str(Path(p).resolve()))
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'work/compat-research/zig-cache');zig=ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
def build(args):
 p=subprocess.run([str(zig)]+args,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=90,env=env)
 with (LAB/'build.txt').open('a')as f:f.write(p.stdout+p.stderr)
 if p.returncode:raise RuntimeError(p.stderr)
(LAB/'build.txt').write_text('')
seed=json.loads((LAB/'seed-routes.json').read_text());routes=seed['Routes'];header=['#define ROUTE_COUNT '+str(len(routes)),'typedef struct {PCWSTR host,privatePath;const char *hostSha,*privateSha;} ROUTE;','static ROUTE routes[]={']
case=['typedef struct {PCWSTR host,old,privatePath;int id;} CASE;','static CASE cases[]={']
for r in routes:
 assert sha(r['Host'])==r['HostSHA']and sha(r['Private'])==r['PrivateSHA']
 header.append('{'+','.join([wide(r['Host']),wide(r['Private']),json.dumps(r['HostSHA']),json.dumps(r['PrivateSHA'])])+'},')
 p=pefile.PE(r['Private']);groups=[]
 for t in p.DIRECTORY_ENTRY_RESOURCE.entries:
  if t.id==14:groups=[e.id for e in t.directory.entries if e.id is not None]
 if groups:case.append('{'+','.join([wide(r['Host']),wide(r['Private']),wide(r['Private']),str(min(groups))])+'},')
header+=['};'];case+=['};','#define CASE_COUNT (sizeof(cases)/sizeof(cases[0]))','#define CONSUMER_PATH '+wide(LAB/'RouteConsumer.dll')]
(LAB/'ProbeCases.h').write_text('\n'.join(case));shutil.copy2(OLD/'RouteConsumer.c',LAB/'RouteConsumer.c')
source=(OLD/'IconRouteProbe.c').read_text().replace('BOOL foreignPreserved=slotChanged&&refusal==ERROR_BUSY&&*slot==foreignLoadImage;', 'DWORD initRefusal=slotChanged?init(NULL):0;BOOL foreignPreserved=slotChanged&&refusal==ERROR_BUSY&&initRefusal==ERROR_BUSY&&*slot==foreignLoadImage;')
(LAB/'RouteProof.c').write_text(source)
build(['cc','-target','x86_64-windows-gnu','-O2','-shared',str(LAB/'RouteConsumer.c'),'-o',str(LAB/'RouteConsumer.dll'),'-luser32'])
routeExe=LAB/'RouteProof.exe';build(['cc','-target','x86_64-windows-gnu','-O2','-municode','-Wl,--subsystem,windows',str(LAB/'RouteProof.c'),'-o',str(routeExe),'-luser32','-lgdi32','-lshell32','-lversion'])
folderExe=OWN/'FolderCacheProbe.exe'
build(['c++','-target','x86_64-windows-gnu','-O2','-std=c++17','-municode','-Wl,--subsystem,windows',str(OWN/'FolderCacheProbe.cpp'),'-o',str(folderExe),'-lole32','-luuid','-lshell32','-luser32','-lgdi32'])
for key,path in [('FIXTURE',folderExe),('ROUTE_FIXTURE',routeExe),('EXPLORER',BASE/'Runtime/Explorer10/explorer.exe')]:header+=['#define '+key+'_PATH '+wide(path),'#define '+key+'_SHA '+json.dumps(sha(path))]
(LAB/'Routes.h').write_text('\n'.join(header))
dll=LAB/'IconRoutes.NoVfs.dll';build(['cc','-target','x86_64-windows-gnu','-O2','-shared',str(LAB/'IconRoutesNoVfs.c'),'-o',str(dll),'-lbcrypt','-lpsapi','-lshell32','-luser32'])
# Reuse only native Win32 declarations; never load USVFS or execute the other
# builder/test body. All target processes below are our exact created handles.
src=(OWN/'CacheNoVfs.py').read_text();exec('class SI'+src.split('class SI',1)[1].split("nonce=uuid.uuid4().hex",1)[0])
nonce=uuid.uuid4().hex;directory=LAB/'sessions'/nonce;directory.mkdir(parents=True);desktopName='OwnRoutesNoVfs_'+nonce;desk=desktopCreate(desktopName,None,None,0,0x1ff,None)
if not desk:raise C.WinError(C.get_last_error())
def run(exe,args,name):
 si=SI();si.cb=C.sizeof(si);si.desktop='WinSta0\\'+desktopName;si.flags=1;si.show=0;pi=PI();cmd=subprocess.list2cmdline([str(exe)]+[str(x)for x in args]);modules=set()
 try:
  if not create(str(exe),C.create_unicode_buffer(cmd),None,None,False,0x08000000,None,str(LAB),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
  for tick in range(600):
   if wait(pi.process,100)==0:break
   values=(W.HMODULE*2048)();needed=W.DWORD()
   if enum(pi.process,values,C.sizeof(values),C.byref(needed))and needed.value<=C.sizeof(values):
    for m in values[:needed.value//C.sizeof(W.HMODULE)]:
     text=C.create_unicode_buffer(32768)
     if moduleName(pi.process,m,text,len(text)):modules.add(text.value)
  killed=wait(pi.process,0)!=0
  if killed:term(pi.process,0xdec9);wait(pi.process,5000)
  code=W.DWORD();exitCode(pi.process,C.byref(code));assert not any('usvfs'in m.lower()for m in modules)
  return dict(Name=name,PID=pi.pid,Exit=code.value,Killed=killed,NoUSVFS=True,Modules=sorted(modules))
 finally:
  if pi.thread:close(pi.thread)
  if pi.process:close(pi.process)
results=[]
try:
 log=directory/'routes.jsonl';r=run(routeExe,[dll,log],'routes');r['Report']=[json.loads(line)for line in log.read_text().splitlines()]if log.exists()else[];results.append(r);print('routes',r['PID'],r['Exit'],flush=True)
 empty=directory/'Empty';empty.mkdir();full=directory/'Full';full.mkdir();(full/'one.txt').write_text('own');(full/'two.txt').write_text('own');custom=directory/'Custom';custom.mkdir()
 private=next(r['Private']for r in routes if Path(r['Host']).name.lower()=='imageres.dll')
 (custom/'desktop.ini').write_text('[.ShellClassInfo]\r\nIconResource='+private+',-3\r\n',encoding='utf-16');assert setAttr(str(custom),1)and setAttr(str(custom/'desktop.ini'),6)
 for mode in ['native','no-vfs','no-vfs-key']:
  out=directory/mode;out.mkdir();r=run(folderExe,[out,empty,full,BASE,'-'if mode=='native'else dll,custom,mode],mode)
  try:r['Report']=json.loads((out/'icons.json').read_text())
  except (OSError,ValueError)as e:r['Report']={'Error':str(e)}
  for icon in r['Report'].get('icons',[]):
   f=out/(icon['name']+'.bgra');icon['pixelsSHA']=sha(f)if f.exists()else None
  results.append(r);print(mode,r['PID'],r['Exit'],flush=True)
finally:closed=desktopClose(desk)
def icon(case,name):return next(i for i in results[case]['Report']['icons']if i['name']==name)['pixelsSHA']
checks=dict(AllOwnedChildrenExited=all(r['Exit']==0 and not r['Killed']for r in results),DesktopClosed=bool(closed),NativeFolder32Differs=icon(1,'empty-fileinfo-100')!=icon(2,'empty-fileinfo-100'),CachedJumboStaysNativeWithoutKey=icon(1,'empty-factory-4')==icon(2,'empty-factory-4'),ScopedPrivateKeyChangesJumbo=icon(1,'empty-factory-4')!=icon(3,'empty-factory-4'),PrivateKeyMatchesExplicitPrivateResource=icon(3,'empty-factory-4')==icon(3,'custom-factory-4'),ForcedOwnThumbnailChangesNative=icon(1,'nonempty-factory-8')!=icon(2,'own-force-thumbnail'),SubsequentThumbnailUsesRefreshedOwnItem=icon(2,'own-force-thumbnail')==icon(2,'after-force-factory-8'),ExplorerEqualsGenuineOld=icon(3,'explorer-native')==icon(3,'explorer-old'))
proof=dict(DLLSHA=sha(dll),Directory=str(directory),DesktopClosed=bool(closed),Results=results,Checks=checks,Passed=all(checks.values()))
(LAB/'own-proof.json').write_text(json.dumps(proof,indent=2))
dependencies=dict(seed['Dependencies']);dependencies['C:\\Windows\\System32\\windows.storage.dll']=sha('C:/Windows/System32/windows.storage.dll')
files={str(p.relative_to(LAB)):sha(p)for p in LAB.iterdir()if p.is_file()and p.name not in ['manifest.json','build.txt','seed-routes.json']and not p.name.endswith(('.stdout.txt','.stderr.txt'))}
manifest=dict(Version=1,Helper=str(dll),InitializeExport='NoVfsIconsInitialize',RestoreExport='NoVfsIconsRestore',Routes=routes,RouteCount=len(routes),Files=files,Dependencies=dependencies,OwnProofPassed=proof['Passed'],LiveTested=False,USVFS=False,LoaderGetProcAddressAlwaysNative=True,RestoreContract='Quiescent own fixture/entry-held only; live rollback terminates exact owned host',CacheKeyScope='CExtractIcon IExtractIconW slot3; genuine-first imageres.dll -3/-4 only')
(LAB/'manifest.json').write_text(json.dumps(manifest,indent=2));print('passed',proof['Passed'],flush=True)
