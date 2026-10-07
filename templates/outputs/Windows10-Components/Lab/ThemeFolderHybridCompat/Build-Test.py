from pathlib import Path
import os,sys,subprocess,hashlib,json
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent.parent
sys.path.insert(0,str(R/'work/pylib'));import pefile
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(R/'work/compat-research/zig-cache');zig=R/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
def run(cmd):
 p=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW,timeout=90)
 with(H/'build.txt').open('a')as f:f.write(p.stdout+p.stderr+'\n')
 if p.returncode:print(p.stderr);raise SystemExit(p.returncode)
base=[str(zig),'c++','-target','x86_64-windows-gnu','-O2','-std=c++17']
origin=B/'Lab/Theme10BrowserProbe';src=(origin/'BrowserProbe.cpp').read_text().replace('#include "ScopedTheme.hpp"','#include "ScopedTheme.hpp"\n#include "FixtureHybrid.hpp"')
src=src.replace('if(old||!wcscmp(argv[2],L"native-loaded"))','capacityMode=!wcscmp(argv[2],L"capacity");generationMode=!wcscmp(argv[2],L"generation");if((capacityMode||generationMode||!wcscmp(argv[2],L"adapter"))&&!fixtureInstall())break;if(generationMode){code=0;break;}\n  if(old||!wcscmp(argv[2],L"native-loaded"))')
src=src.replace('if(!scoped.close())code=1;','if((capacityMode||generationMode||!wcscmp(argv[2],L"adapter"))&&!fixtureRestore())code=1;if(!scoped.close())code=1;')
src=src.replace('if(argc!=5)return 2;Input input=', 'if(argc!=5)return 2;if(!SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2))return 20;Input input=')
(H/'Fixture.cpp').write_text(src)
run(base+['-municode','-Wl,--subsystem,windows','-I'+str(origin),str(H/'Fixture.cpp'),'-o',str(H/'HybridFixture.exe'),'-lole32','-luuid','-luser32','-lshell32','-luxtheme','-lbcrypt','-lgdi32'])
ux=Path('C:/Windows/System32/uxtheme.dll');dui=Path('C:/Windows/System32/dui70.dll');old=B/'Image/4/Windows/Resources/Themes/aero/aero.msstyles';native=Path('C:/Windows/Resources/Themes/aero/aero.msstyles');U=pefile.PE(str(ux));D=pefile.PE(str(dui));lines=['struct GUARD{DWORD rva;size_t size;const BYTE*bytes;};']
def guards(name,pe,spans):
 for i,(r,z)in enumerate(spans):lines.append(f'static const BYTE {name}{i}[]={{'+','.join(hex(x)for x in pe.get_data(r,z))+'};')
 lines.append(f'static const GUARD {name}Guards[]={{'+','.join(f'{{0x{r:x},{z},{name}{i}}}'for i,(r,z)in enumerate(spans))+'};')
spans=[]
for r in [0x4720,0xa7f8,0x2c210,0x493f0,0x609c0,0x5f7c0]:
 e=next(e.struct for e in U.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress==r);spans.append((r,e.EndAddress-r))
guards('ux',U,spans);spans=[];thunks=[]
for name,iat in [('OpenThemeDataForDpi',0x1973b8),('GetThemeColor',0x197398)]:
 entry=next(d for d in D.DIRECTORY_ENTRY_DELAY_IMPORT if any(i.name==name.encode()for i in d.imports));imp=next(i for i in entry.imports if i.name==name.encode());assert imp.address-D.OPTIONAL_HEADER.ImageBase==iat
 idx=(iat-entry.struct.pIAT)//8;thunk=D.get_qword_at_rva(iat)-D.OPTIONAL_HEADER.ImageBase;thunks.append(thunk);hint=D.get_qword_at_rva(entry.struct.pINT+idx*8)
 spans += [(thunk,12),(entry.struct.pINT+idx*8,8),(hint,2+len(name)+1),(D.get_rva_from_offset(entry.struct.get_file_offset()),32),(entry.struct.szName,len(entry.dll)+1)]
for r in [0x26df8,0x2e8e0]:
 e=next(e.struct for e in D.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress==r);spans.append((r,e.EndAddress-r))
guards('dui',D,spans);lines.append('static const DWORD thunks[]={'+','.join(hex(x)for x in thunks)+'};')
deps=[('UX',ux),('DUI',dui),('OLD_AERO',old),('NATIVE_AERO',native),('EXPLORER',B/'Runtime/Explorer10/explorer.exe'),('FIXTURE',H/'HybridFixture.exe')]
for label,p in deps:lines.extend(['#define '+label+'_PATH L'+json.dumps(str(p)),'#define '+label+'_SHA "'+hashlib.sha256(p.read_bytes()).hexdigest()+'"'])
for label,n in [('DPI','OpenThemeDataForDpi'),('COLOR','GetThemeColor')]:lines.append('#define '+label+'_RVA '+hex(next(x.address for x in U.DIRECTORY_ENTRY_EXPORT.symbols if x.name==n.encode())))
(H/'Pins.h').write_text('\n'.join(lines))
run(base+['-shared',str(H/'ThemeFolderHybrid.cpp'),'-o',str(H/'ThemeFolderHybrid.dll'),'-luser32','-luxtheme','-lbcrypt','-lpsapi'])
results=[]
for mode in ['old','adapter','capacity','generation']:
 log=H/(mode+'.txt');p=subprocess.Popen([str(H/'HybridFixture.exe'),str(log),mode,str(origin/'OwnFolder'),str(old)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
 try:out,err=p.communicate(timeout=22);killed=False
 except subprocess.TimeoutExpired:p.kill();out,err=p.communicate(timeout=5);killed=True
 text=log.read_text(errors='replace')if log.exists()else'';print(text);print(mode,p.pid,p.returncode,killed)
 results.append(dict(mode=mode,pid=p.pid,exit=p.returncode,killed=killed,log=text,stderr=err.decode(errors='replace')))
passed=all(not r['killed']and'desktopCloseAfterThreadExit=1'in r['log']and((r['mode']=='old'and r['exit']==1 and'BrowseToIDList=80004005'in r['log'])or(r['mode']in ['adapter','capacity']and r['exit']==0 and'FIXTURE_PASS=1'in r['log']and'folderMatched=1'in r['log'])or(r['mode']=='generation'and r['exit']==0 and'FIXTURE_PASS=1'in r['log']and'foreignStaleHandleRejectedBeforeNative pass=1'in r['log']))for r in results)
files={n:hashlib.sha256((H/n).read_bytes()).hexdigest()for n in ['ThemeFolderHybrid.cpp','ThemeFolderHybrid.dll','Fixture.cpp','FixtureHybrid.hpp','HybridFixture.exe','Pins.h','Build-Test.py']}
(H/'own-proof.json').write_text(json.dumps(dict(Pass=passed,OwnFixtureOnly=True,results=results,Files=files),indent=2))
manifest=dict(Version=2,ProductionLiveTested=False,OwnProofPassed=passed,InitializeExport='ThemeFolderHybridInitialize',RestoreExport='ThemeFolderHybridRestore',StateExport='ThemeFolderHybridState',StateSize=160,Files=files,Dependencies={str(p):hashlib.sha256(p.read_bytes()).hexdigest()for n,p in deps if n!='FIXTURE'})
(H/'manifest.json').write_text(json.dumps(manifest,indent=2));raise SystemExit(0 if passed else 1)
