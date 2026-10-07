"""Separate opt-in full-old theme with exact real-native ItemsView color fallback."""
import ctypes as C,struct,json,hashlib,importlib.util
from ctypes import wintypes as W
from pathlib import Path
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1]
def module(path,name):s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
scoped=module(BASE/'Lab/ControlThemeBootstrap/Launch-ControlTheme10.py','hybrid_primary_call')
exports=scoped.exports;sha=scoped.sha;primary_call=scoped.primary_call
def install_hybrid_theme10(boot):
 if not boot.primary_suspended or not boot.entry_restored or not boot.entry:raise RuntimeError('Only new owned restored entry-held primary accepted')
 manifest=json.loads((LAB/'manifest.json').read_text())
 for x in manifest['Files']:
  if sha(x['Path'])!=x['SHA256']:raise RuntimeError('Hybrid pin differs '+x['Path'])
 if boot.exe.resolve()!=(BASE/'Runtime/Explorer10/explorer.exe').resolve():raise RuntimeError('Hybrid host role differs')
 fn=boot.k.GetProcessTimes;fn.argtypes=[W.HANDLE,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p];fn.restype=W.BOOL
 born,end,kernel,user=(C.c_ulonglong() for _ in range(4));now=C.c_ulonglong();boot.k.GetSystemTimeAsFileTime.argtypes=[C.c_void_p];boot.k.GetSystemTimeAsFileTime(C.byref(now))
 if not fn(boot.pi.process,C.byref(born),C.byref(end),C.byref(kernel),C.byref(user)) or not 0<=now.value-born.value<=180*10000000:raise RuntimeError('Hybrid target is not fresh')
 tid=boot.k.GetProcessIdOfThread;tid.argtypes=[W.HANDLE];tid.restype=W.DWORD
 if tid(boot.pi.thread)!=boot.pi.pid:raise RuntimeError('Hybrid primary thread belongs elsewhere')
 if boot.attached:boot.finish(detach=True,resume_primary=False)
 identity=module(BASE/'Launch-TouchpadCompat.py','hybrid_identity');helper=BASE/'Lab/ThemeFolderHybridCompat/ThemeFolderHybrid.dll';helperBase=boot.load_library(helper);helperMap=identity.mapped_file_identity(boot,helperBase,helper)
 bridge=LAB/'PrimaryBridge.dll';bridgeBase=boot.load_library(bridge);bridgeMap=identity.mapped_file_identity(boot,bridgeBase,bridge)
 args=boot.alloc(boot.pi.process,None,4096,0x3000,4);boot.patch(args,struct.pack('<QQ',helperBase,helperBase+exports(helper)['ThemeFolderHybridInitialize']));finished=False
 try:code=primary_call(boot,bridgeBase+exports(bridge)['HybridBootstrapInitialize'],args);finished=True
 finally:
  if finished:boot.free(boot.pi.process,args,0,0x8000)
 dpi=struct.unpack('<16I4Q',boot.read(bridgeBase+exports(bridge)['HybridBootstrapState'],96));state=struct.unpack('<16I12Q',boot.read(helperBase+exports(helper)['ThemeFolderHybridState'],160))
 dpinames=['Size','Version','Result','Complete','PrimaryThread','ProcessBefore','ProcessAfter','ThreadBefore','ThreadAfter','ProcessSame','ThreadSame','PMv2Before','PMv2After','DPIBefore','DPIAfter','InitializerResult','ProcessContextBefore','ProcessContextAfter','ThreadContextBefore','ThreadContextAfter']
 names=['Size','Version','Result','Active','FullTheme','Fallback8','Fallback11','NativePass','Tracked','Rejected','Failures','Restores','Quarantined','DPIStable','NativeHeaderFallbacks','GenerationRejected','OldFile','NativeFallbackFile','Slot0','Slot1','Original0','Original1','Replacement0','Replacement1','ProcessDPIBefore','ProcessDPIAfter','ThreadDPIBefore','ThreadDPIAfter']
 report=dict(Installed=not code,helperBase=hex(helperBase),helperSHA256=sha(helper),manifestSHA256=sha(LAB/'manifest.json'),bridgeBase=hex(bridgeBase),bridgeSHA256=sha(bridge),PhysicalHelper=helperMap,PhysicalBridge=bridgeMap,DPI=dict(zip(dpinames,dpi)),Hybrid=dict(zip(names,state)),Scope='Private full old theme; exact native missing Header TEXTCOLOR3803 states8/11 fallback')
 if code or dpi[0]!=96 or dpi[1]!=1 or dpi[2] or dpi[3]!=1 or dpi[4]!=boot.pi.tid or not dpi[9] or not dpi[10] or dpi[11]!=dpi[12] or dpi[13]!=96 or dpi[14]!=96 or state[0]!=160 or state[1]!=2 or state[2] or state[3]!=1 or state[4]!=1 or state[10] or state[12] or state[13]!=1 or state[15] or not state[16] or not state[17] or state[16]==state[17]:raise RuntimeError('Hybrid init/readback refuses '+json.dumps(report))
 for index in range(2):
  if struct.unpack('<Q',boot.read(state[18+index],8))[0]!=state[22+index]:raise RuntimeError('Hybrid actual import publication differs')
 ux=next(v for n,v in boot.modules().items() if n.endswith('\\uxtheme.dll'));app=struct.unpack('<Q',boot.read(ux+0x9cab8,8))[0]
 if not app or struct.unpack('<Q',boot.read(app+8,8))[0]!=state[16]:raise RuntimeError('Actual process current theme is not private old provider')
 report['OldCurrentVerified']=True;report['CurrentThemePointerAddress']=app+8;return report
