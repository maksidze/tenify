from pathlib import Path
import os,sys,subprocess,hashlib,json
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent.parent
sys.path.insert(0,str(R/'work/pylib'));import pefile
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(R/'work/compat-research/zig-cache');zig=R/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
def run(cmd):
 p=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW,timeout=90)
 (H/'build.txt').open('a').write(' '.join(map(str,cmd))+'\n'+p.stdout+p.stderr+'\n');assert p.returncode==0,p.stderr
base=[str(zig),'c++','-target','x86_64-windows-gnu','-O2','-std=c++17']
run(base+['-municode','-Wl,--subsystem,windows',str(H/'Fixture.cpp'),'-o',str(H/'ControlFixture.exe'),'-lole32','-luuid','-luser32','-lshell32','-luxtheme','-lbcrypt','-lgdi32'])
ux=Path('C:/Windows/System32/uxtheme.dll');cc=Path('C:/Windows/WinSxS/amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.26100.5074_none_3e0d6f78e32fd63f/comctl32.dll');old=B/'Image/4/Windows/Resources/Themes/aero/aero.msstyles'
U=pefile.PE(str(ux));C=pefile.PE(str(cc));lines=['struct GUARD {DWORD rva;size_t size;const BYTE*bytes;};']
def guards(name,pe,spans):
 for i,(rva,size) in enumerate(spans):lines.append(f'static const BYTE {name}{i}[]={{'+','.join(hex(x)for x in pe.get_data(rva,size))+'};')
 lines.append(f'static const GUARD {name}Guards[]={{'+','.join(f'{{0x{r:x},{z},{name}{i}}}'for i,(r,z)in enumerate(spans))+'};')
uxspans=[]
for r in [0x4720,0xa7f8,0x2c210,0x493f0]:
 e=next(e.struct for e in U.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress==r);uxspans.append((r,e.EndAddress-r))
guards('ux',U,uxspans)
ccspans=[];thunks=[]
for name,iat in [('OpenThemeData',0x243450),('OpenThemeDataForDpi',0x243550)]:
 entry=next(d for d in C.DIRECTORY_ENTRY_DELAY_IMPORT if any(i.name==name.encode()for i in d.imports));imp=next(i for i in entry.imports if i.name==name.encode())
 assert imp.address-C.OPTIONAL_HEADER.ImageBase==iat
 idx=(iat-entry.struct.pIAT)//8;raw=C.get_qword_at_rva(iat);thunk=raw-C.OPTIONAL_HEADER.ImageBase;thunks.append(thunk)
 # Complete initial delay-import instruction stub and descriptor/name bindings.
 hint=C.get_qword_at_rva(entry.struct.pINT+idx*8)
 ccspans += [(thunk,12),(entry.struct.get_file_offset(),0)] if False else [(thunk,12),(entry.struct.pINT+idx*8,8),(hint,2+len(name)+1)]
 ccspans += [(C.get_rva_from_offset(entry.struct.get_file_offset()),32),(entry.struct.szName,len(entry.dll)+1)]
guards('cc',C,ccspans)
lines.append('static const DWORD thunks[]={'+','.join(hex(x)for x in thunks)+'};')
for label,path in [('UX',ux),('CC',cc),('OLD_AERO',old),('EXPLORER',B/'Runtime/Explorer10/explorer.exe'),('FIXTURE',H/'ControlFixture.exe')]:
 lines.append('#define '+(label if label=='OLD_AERO' else label+'_PATH')+' L'+json.dumps(str(path)))
 lines.append('#define '+label+'_SHA "'+hashlib.sha256(path.read_bytes()).hexdigest()+'"')
for label,name in [('OPEN','OpenThemeData'),('DPI','OpenThemeDataForDpi')]:lines.append(f'#define {label}_RVA '+hex(next(e.address for e in U.DIRECTORY_ENTRY_EXPORT.symbols if e.name==name.encode())))
(H/'Pins.h').write_text('\n'.join(lines))
run(base+['-shared',str(H/'AppControlTheme10.cpp'),'-o',str(H/'AppControlTheme10.dll'),'-luser32','-luxtheme','-lbcrypt','-lpsapi'])
folder=H/'OwnFolder';folder.mkdir(exist_ok=True);(folder/'fixture.txt').write_text('Own control/folder fixture.\n');log=H/'own-fixture.txt'
env['APP_THEME_FIXTURE_SHA']=hashlib.sha256((H/'ControlFixture.exe').read_bytes()).hexdigest()
p=subprocess.Popen([str(H/'ControlFixture.exe'),str(log),'controls',str(folder),str(old)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
try:out,err=p.communicate(timeout=22);killed=False
except subprocess.TimeoutExpired:p.kill();out,err=p.communicate(timeout=5);killed=True
text=log.read_text(errors='replace')if log.exists()else'';print(text);print('exit',p.returncode,'pid',p.pid,'killed',killed)
proof={'Exit':p.returncode,'Pid':p.pid,'Killed':killed,'NeverSwitchedDesktop':True,'Log':text,'stderr':err.decode(errors='replace'),'Files':{n:hashlib.sha256((H/n).read_bytes()).hexdigest()for n in ['Fixture.cpp','FixtureControls.hpp','AppControlTheme10.cpp','AppControlTheme10.dll','ControlFixture.exe','Pins.h']}}
(H/'own-proof.json').write_text(json.dumps(proof,indent=2));raise SystemExit(p.returncode)
