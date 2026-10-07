from pathlib import Path
import sys,json,hashlib,subprocess,os
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent.parent
sys.path.insert(0,str(R/'work/pylib'));import pefile
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
q=lambda p:'L'+json.dumps(str(p))
native=Path('C:/Windows/System32');pcs=Path('C:/Windows/System32/twinui.pcshell.dll')
specs=[('uxtheme.dll',native/'uxtheme.dll',0xa40e0,0x3fbb7,[(0x3fb78,64)]),('twinui.pcshell.dll',pcs,0x9050a0,0x65f19e,[(0x65f030,32),(0x65f17f,32)]),('shell32.dll',native/'shell32.dll',0x731728,0x552fc2,[(0x552e54,32),(0x552fa3,32)])]
out=['typedef struct{DWORD rva,length;const BYTE*bytes;} GUARD;','typedef struct{PCWSTR baseName,path;const char*sha;DWORD iat,caller,thunk,guardCount;const GUARD*guards;} SPEC;'];meta=[]
for index,(name,path,iat,caller,ranges) in enumerate(specs):
 pe=pefile.PE(str(path));entry=next((d,x)for d in pe.DIRECTORY_ENTRY_DELAY_IMPORT for x in d.imports if x.address-pe.OPTIONAL_HEADER.ImageBase==iat);d,imp=entry
 print('delay',name,d.dll,imp.name,d.struct.grAttrs)
 assert imp.name==b'DwmSetWindowAttribute' and d.struct.grAttrs==1
 thunk=int.from_bytes(pe.get_data(iat,8),'little')-pe.OPTIONAL_HEADER.ImageBase
 idx=(iat-d.struct.pIAT)//8;intRva=d.struct.pINT+8*idx;nameRva=int.from_bytes(pe.get_data(intRva,8),'little')
 ranges +=[(thunk,12),(d.struct.get_file_offset(),0)] if False else []
 ranges +=[(thunk,12),(pe.get_rva_from_offset(d.struct.get_file_offset()),32),(intRva,8),(d.struct.szName,len(d.dll)+1),(nameRva,2+len(imp.name)+1)]
 guards=[]
 for j,(rva,length) in enumerate(ranges):
  data=pe.get_data(rva,length);assert len(data)==length
  out.append(f'static const BYTE g{index}_{j}[]={{'+','.join(hex(b)for b in data)+'};');guards.append(f'{{0x{rva:x},{length},g{index}_{j}}}')
 out.append(f'static const GUARD guards{index}[]={{'+','.join(guards)+'};')
 meta.append({'name':name,'path':str(path),'sha256':sha(path),'iat':iat,'caller':caller,'thunk':thunk,'guards':[{'rva':a,'bytes':pe.get_data(a,n).hex()}for a,n in ranges]})
out.append('static const SPEC specs[]={'+','.join('{'+f'{q(x["name"])},{q(x["path"])},"{x["sha256"]}",0x{x["iat"]:x},0x{x["caller"]:x},0x{x["thunk"]:x},{len(x["guards"])},guards{i}'+'}'for i,x in enumerate(meta))+'};')
dwm=native/'dwmapi.dll';pe=pefile.PE(str(dwm));exp=next(x for x in pe.DIRECTORY_ENTRY_EXPORT.symbols if x.name==b'DwmSetWindowAttribute');assert not exp.forwarder
out +=[f'#define DWM_PATH {q(dwm)}',f'#define DWM_SHA "{sha(dwm)}"',f'#define DWM_EXPORT_RVA 0x{exp.address:x}']
# Both native renderer implementations have the same exact typed array/arguments;
# each pointer is selected only after its own instruction/hash/mapping guards.
renderer=(H.parent/'NativeWinXCompat/Renderer.h').read_text();a=renderer.index('static HRESULT rendererInitialize(');z=renderer.index('static bool rendererContainsMenu',a)
defs=[];body=['static HRESULT rendererSelect(BYTE*base,int kind){',' if(kind!=1&&kind!=2)return E_INVALIDARG;']
for kind,path,rvas in [(1,pcs,[0x6611f4,0x661b18,0x65f754,0x4c1184]),(2,native/'shell32.dll',[0x127fd8,0x12858c,0x15db9c,0x1f5498])]:
 pe=pefile.PE(str(path));body.append(f' if(kind=={kind}){{')
 for j,rva in enumerate(rvas):
  data=pe.get_data(rva,32);defs.append(f'static const BYTE rg{kind}_{j}[]={{'+','.join(hex(b)for b in data)+'};');body.append(f'  if(memcmp(base+0x{rva:x},rg{kind}_{j},32))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);')
 for field,typeName,rva in zip(['rendererApply','rendererRemove','rendererProc','rendererDestroy'],['RendererApplyFn','RendererRemoveFn','RendererProcFn','RendererDestroyFn'],rvas):body.append(f'  {field}=({typeName})(base+0x{rva:x});')
 body.append(' }')
body+=[' WinXRendererTrace[0]=1;return S_OK;}']
renderer=renderer[:a]+'\n'.join(body)+'\n'+renderer[z:];renderer=renderer.replace('#include "RendererGuards.h"','\n'.join(defs)+'\nstatic const BYTE shellFixtureHash[]={'+','.join(hex(b)for b in bytes.fromhex(sha(native/'shell32.dll')))+'};')
(H/'RendererSelect.h').write_text(renderer)
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(R/'work/compat-research/zig-cache');zig=R/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
libs=['-lole32','-luuid','-lapi-ms-win-core-winrt-string-l1-1-0','-lapi-ms-win-core-winrt-l1-1-0','-luser32','-lshell32','-lbcrypt','-lpsapi','-ldwmapi','-lgdi32']
def runBuild(source,target,dll=False):
 cmd=[str(zig),'cc'if dll else'c++','-target','x86_64-windows-gnu','-O2', '-shared'if dll else'-municode','-Wl,--subsystem,windows',str(H/source),'-o',str(H/target)]+libs
 if not dll:cmd.insert(6,'-std=c++17')
 p=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW,timeout=90);(H/(source+'.build.txt')).write_text(p.stdout+p.stderr);print('compile',source,p.returncode)
 if p.returncode:print(p.stderr);raise SystemExit(p.returncode)
runBuild('Fixture.cpp','MenuSquareV2Fixture.exe')
explorer=B/'Runtime/Explorer10/explorer.exe'
out +=[f'#define FIXTURE_PATH {q(H/"MenuSquareV2Fixture.exe")}',f'#define FIXTURE_SHA "{sha(H/"MenuSquareV2Fixture.exe")}"',f'#define EXPLORER_PATH {q(explorer)}',f'#define EXPLORER_SHA "{sha(explorer)}"']
out += [f'#define ALT_FIXTURE_PATH {q(H.parent/"NativeMenuThemeColorCompat/MenuThemeFixture.exe")}',f'#define ALT_FIXTURE_SHA "{sha(H.parent/"NativeMenuThemeColorCompat/MenuThemeFixture.exe")}"']
(H/'Guard.h').write_text('\n'.join(out));(H/'native-guards.json').write_text(json.dumps(meta,indent=2))
runBuild('MenuSquareV2.c','MenuSquareV2.dll',True)
p=subprocess.run([str(H/'MenuSquareV2Fixture.exe'),str(H/'own-proof.txt'),str(H/'MenuSquareV2.dll')],capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=22)
text=(H/'own-proof.txt').read_text();print('fixture exit',p.returncode);print(text)
(H/'own-proof.json').write_text(json.dumps({'exitCode':p.returncode,'fixtureSha256':sha(H/'MenuSquareV2Fixture.exe'),'helperSha256':sha(H/'MenuSquareV2.dll'),'transcript':text,'noInteractiveDesktop':True,'noInputOrCommands':True},indent=2));raise SystemExit(p.returncode)
