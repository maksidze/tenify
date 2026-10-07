"""Exact private MENU part compatibility, only in a fresh entry-held Explorer."""
import ctypes as C,struct,json,importlib.util
from ctypes import wintypes as W
from pathlib import Path
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1]
def module(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
scoped=module(BASE/'Lab/ControlThemeBootstrap/Launch-ControlTheme10.py','menu_primary_call')
exports=scoped.exports;sha=scoped.sha;primary_call=scoped.primary_call
STATE_NAMES=['Size','Version','Result','Active','MappedPlain','MappedPCS','MappedShell','Passed','Rejected','GenerationRejected','Failures','Restores','CodeSites','IATSlots','Quarantined','Reserved','OldFile','App','UX','PCS','Shell','CallTable','IATTable','ProcessDPIBefore','ProcessDPIAfter','ThreadDPIBefore','ThreadDPIAfter','OldReference']
def install_theme_menu(boot,hybrid):
 if not boot.primary_suspended or not boot.entry_restored or not boot.entry or boot.attached:raise RuntimeError('Menu adapter needs fresh owned detached entry-held primary')
 if boot.exe.resolve()!=(BASE/'Runtime/Explorer10/explorer.exe').resolve():raise RuntimeError('Menu adapter host role differs')
 if not hybrid.get('Installed') or not hybrid.get('OldCurrentVerified'):raise RuntimeError('Private hybrid theme prerequisite missing')
 manifest=json.loads((LAB/'manifest.json').read_text())
 for row in manifest['Files']:
  if sha(row['Path'])!=row['SHA256']:raise RuntimeError('Menu adapter dependency changed '+row['Path'])
 fn=boot.k.GetProcessTimes;fn.argtypes=[W.HANDLE,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p];fn.restype=W.BOOL
 born,end,kernel,user=(C.c_ulonglong() for _ in range(4));now=C.c_ulonglong();boot.k.GetSystemTimeAsFileTime.argtypes=[C.c_void_p];boot.k.GetSystemTimeAsFileTime(C.byref(now))
 if not fn(boot.pi.process,C.byref(born),C.byref(end),C.byref(kernel),C.byref(user)) or not 0<=now.value-born.value<=180*10000000:raise RuntimeError('Menu target is not fresh')
 tid=boot.k.GetProcessIdOfThread;tid.argtypes=[W.HANDLE];tid.restype=W.DWORD
 if tid(boot.pi.thread)!=boot.pi.pid:raise RuntimeError('Menu primary belongs elsewhere')
 identity=module(BASE/'Launch-TouchpadCompat.py','menu_identity');helper=BASE/'Lab/NativeThemeMenuCompat/ThemeMenuCompat.dll';helperBase=boot.load_library(helper);helperMap=identity.mapped_file_identity(boot,helperBase,helper)
 bridge=LAB/'PrimaryBridge.dll';bridgeBase=boot.load_library(bridge);bridgeMap=identity.mapped_file_identity(boot,bridgeBase,bridge)
 args=boot.alloc(boot.pi.process,None,4096,0x3000,4);boot.patch(args,struct.pack('<QQ',helperBase,helperBase+exports(helper)['ThemeMenuInitialize']));finished=False
 try:code=primary_call(boot,bridgeBase+exports(bridge)['MenuBootstrapInitialize'],args);finished=True
 finally:
  if finished:boot.free(boot.pi.process,args,0,0x8000)
 dpi=struct.unpack('<16I4Q',boot.read(bridgeBase+exports(bridge)['MenuBootstrapState'],96));state=struct.unpack('<16I12Q',boot.read(helperBase+exports(helper)['ThemeMenuState'],160))
 report=dict(Installed=not code,helperBase=hex(helperBase),helperSHA256=sha(helper),manifestSHA256=sha(LAB/'manifest.json'),bridgeBase=hex(bridgeBase),bridgeSHA256=sha(bridge),PhysicalHelper=helperMap,PhysicalBridge=bridgeMap,State=dict(zip(STATE_NAMES,state)),DPI=list(dpi),Scope='Exact native MENU callers: part27 to genuine old part14; other classes unchanged')
 if code or dpi[0]!=96 or dpi[1]!=1 or dpi[2] or dpi[3]!=1 or dpi[4]!=boot.pi.tid or not dpi[9] or not dpi[10] or dpi[11]!=dpi[12] or dpi[13]!=96 or dpi[14]!=96 or state[0]!=160 or state[1]!=1 or state[2] or state[3]!=1 or state[9] or state[10] or state[14] or state[12]!=17 or state[13]!=0 or state[22]!=0 or not state[27]:raise RuntimeError('Menu init/readback refused '+json.dumps(report))
 if state[16]!=hybrid['Hybrid']['OldFile'] or state[17]+8!=hybrid['CurrentThemePointerAddress'] or struct.unpack('<Q',boot.read(state[17]+8,8))[0]!=state[16]:raise RuntimeError('Menu adapter current provider differs')
 # Verify every published call independently of helper counters.
 producer=json.loads((BASE/'Lab/NativeThemeMenuCompat/manifest.json').read_text())
 rows=[];bases=state[18:21];helperSize=scoped.pefile.PE(str(helper),fast_load=True).OPTIONAL_HEADER.SizeOfImage
 if not helperBase<=state[21] or state[21]+17*56>helperBase+helperSize:raise RuntimeError('Menu call table is outside pinned helper')
 for i in range(17):
  row=struct.unpack('<4I2Q8s8s2I',boot.read(state[21]+i*56,56))
  mod,rva,length,api,address,thunk,before,after,protection,published=row
  expected=producer['CallSites'][i]
  if (mod,rva,length,api,before[:length].hex())!=(expected['module'],expected['rva'],expected['length'],expected['api'],expected['expected']):raise RuntimeError('Menu call differs from pinned producer contract '+str(i))
  if mod>2 or length not in (5,6,7) or address!=bases[mod]+rva or published!=1 or boot.read(address,length)!=after[:length]:raise RuntimeError('Menu call publication mismatch '+str(i))
  if after[0]!=0xe8 or address+5+struct.unpack('<i',after[1:5])[0]!=thunk:raise RuntimeError('Menu call island mismatch '+str(i))
  island=boot.read(thunk,12)
  target=struct.unpack('<Q',island[2:10])[0]
  if island[:2]!=b'\x48\xb8' or island[10:]!=b'\xff\xe0' or not helperBase<=target<helperBase+helperSize:raise RuntimeError('Menu island target differs '+str(i))
  rows.append(dict(Module=mod,RVA=hex(rva),API=api,Address=hex(address),Thunk=hex(thunk),Original=before[:length].hex(),Replacement=after[:length].hex(),Published=True))
 report['NativeImages']=[identity.mapped_file_identity(boot,bases[i],Path(path))for i,path in enumerate(['C:/Windows/System32/uxtheme.dll','C:/Windows/System32/twinui.pcshell.dll','C:/Windows/System32/shell32.dll'])]
 report['Calls']=rows
 report['CurrentThemePointerAddress']=state[17]+8
 return report
