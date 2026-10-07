"""Opt-in ONLY: owned new signed Explorer held at restored executable entry."""
import ctypes as C,hashlib,json,struct,time,sys,importlib.util
from ctypes import wintypes as W
from pathlib import Path
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1]
sys.path.insert(0,str(BASE.parents[1]/'work/pylib'));import pefile
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def exports(path):return {e.name.decode():e.address for e in pefile.PE(str(path)).DIRECTORY_ENTRY_EXPORT.symbols if e.name}
def primary_call(boot,function,argument,timeout=20):
 if not boot.primary_suspended or boot.attached:raise RuntimeError('Requires debugger-detached, explicitly entry-held own primary')
 raw=C.create_string_buffer(1248);ctx=(C.addressof(raw)+15)&~15;C.memset(ctx,0,1232);C.c_uint32.from_address(ctx+48).value=0x10000b
 if not boot.get_context(boot.pi.thread,ctx):raise C.WinError(C.get_last_error())
 saved=C.string_at(ctx,1232);rip=struct.unpack_from('<Q',saved,248)[0];rsp=struct.unpack_from('<Q',saved,152)[0]
 if rip!=boot.entry or rsp&15!=8:raise RuntimeError('Primary RIP/stack is not exact restored PE entry')
 mem=boot.alloc(boot.pi.process,None,4096,0x3000,0x40)
 if not mem:raise C.WinError(C.get_last_error())
 done=mem+512
 code=b'\x48\x83\xec\x28\x48\xb9'+struct.pack('<Q',argument)+b'\x48\xb8'+struct.pack('<Q',function)+b'\xff\xd0\x48\x83\xc4\x28\x48\xb9'+struct.pack('<Q',done)+b'\x89\x01\xc6\x41\x04\x01\xeb\xfe'
 boot.patch(mem,code,True);C.c_uint64.from_address(ctx+248).value=mem
 if not boot.set_context(boot.pi.thread,ctx):raise C.WinError(C.get_last_error())
 running=False
 try:
  running=True
  if boot.resume(boot.pi.thread)!=1:raise RuntimeError('Primary suspend count differs; exact-host abort required')
  deadline=time.monotonic()+timeout
  while time.monotonic()<deadline:
   value=boot.read(done,8)
   if value[4]:break
   if boot.wait(boot.pi.process,0)==0:raise RuntimeError('Owned child exited during primary install')
   time.sleep(.02)
  else:raise TimeoutError('Primary call timeout: abort exact owned host, never resume partially installed process')
  if boot.suspend(boot.pi.thread)!=0:raise RuntimeError('Unexpected primary suspend count after completion')
  running=False;C.memmove(ctx,saved,1232)
  if not boot.set_context(boot.pi.thread,ctx):raise C.WinError(C.get_last_error())
  return struct.unpack_from('<I',value)[0]
 finally:
  # On timeout, code may still execute and cannot be freed/restored safely.
  # Root launcher MUST abort this exact child; no cleanup success is invented.
  if not running:boot.free(boot.pi.process,mem,0,0x8000)
def install_control_theme10(bootstrap):
 boot=bootstrap;manifest=json.loads((LAB/'manifest.json').read_text())
 if not boot.primary_suspended or not boot.entry_restored or not boot.entry:raise RuntimeError('Requires restored PE entry and explicit own-primary suspension before any load')
 for item in manifest['Files']:
  if sha(item['Path'])!=item['SHA256']:raise RuntimeError('Control theme bootstrap pin differs: '+item['Path'])
 expected=BASE/'Runtime/Explorer10/explorer.exe'
 if boot.exe.resolve()!=expected.resolve():raise RuntimeError('Host role differs')
 processTimes=boot.k.GetProcessTimes;processTimes.argtypes=[W.HANDLE,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p];processTimes.restype=W.BOOL
 born,end,kernel,user=(C.c_ulonglong() for _ in range(4));now=C.c_ulonglong();boot.k.GetSystemTimeAsFileTime.argtypes=[C.c_void_p];boot.k.GetSystemTimeAsFileTime(C.byref(now))
 if not processTimes(boot.pi.process,C.byref(born),C.byref(end),C.byref(kernel),C.byref(user)) or not 0<=now.value-born.value<=180*10000000:raise RuntimeError('Host is not a fresh owned entry-held process')
 getpid=boot.k.GetProcessIdOfThread;getpid.argtypes=[W.HANDLE];getpid.restype=W.DWORD
 if getpid(boot.pi.thread)!=boot.pi.pid:raise RuntimeError('Primary thread owner differs')
 if boot.attached:boot.finish(detach=True,resume_primary=False)
 identitySpec=importlib.util.spec_from_file_location('control_theme_identity',BASE/'Launch-TouchpadCompat.py');identity=importlib.util.module_from_spec(identitySpec);identitySpec.loader.exec_module(identity)
 helper=BASE/'Lab/ControlTheme10Compat/ControlTheme10.dll';helperBase=boot.load_library(helper)
 helperIdentity=identity.mapped_file_identity(boot,helperBase,helper)
 bridge=LAB/'PrimaryBridge.dll';bridgeBase=boot.load_library(bridge);bridgeIdentity=identity.mapped_file_identity(boot,bridgeBase,bridge)
 args=struct.pack('<QQ',helperBase,helperBase+exports(helper)['ControlTheme10Initialize']);memory=boot.alloc(boot.pi.process,None,4096,0x3000,4);boot.patch(memory,args)
 finished=False
 try:result=primary_call(boot,bridgeBase+exports(bridge)['ControlBootstrapInitialize'],memory);finished=True
 finally:
  if finished:boot.free(boot.pi.process,memory,0,0x8000)
 dpi=struct.unpack('<16I4Q',boot.read(bridgeBase+exports(bridge)['ControlBootstrapState'],96))
 theme=struct.unpack('<16I8Q',boot.read(helperBase+exports(helper)['ControlTheme10State'],128))
 names=['size','version','result','complete','primaryThread','processBefore','processAfter','threadBefore','threadAfter','processSame','threadSame','pmv2Before','pmv2After','dpiBefore','dpiAfter','initializerResult','processContextBefore','processContextAfter','threadContextBefore','threadContextAfter']
 report=dict(Installed=not result,helperBase=hex(helperBase),helperSHA256=sha(helper),bridgeBase=hex(bridgeBase),bridgeSHA256=sha(bridge),manifestSHA256=sha(LAB/'manifest.json'),PhysicalHelper=helperIdentity,PhysicalBridge=bridgeIdentity,DPI=dict(zip(names,dpi)),Theme=dict(Size=theme[0],Version=theme[1],Result=theme[2],Active=theme[3],OldOpenFailures=theme[11],Quarantined=theme[13],Retained=theme[14],SeparateFile=hex(theme[16]),NativeCurrent=hex(theme[17])),Scope='Button/Edit/ComboBox common-controls96 only')
 if result or dpi[0]!=96 or dpi[1]!=1 or dpi[2] or dpi[3]!=1 or dpi[4]!=boot.pi.tid or not dpi[9] or not dpi[10] or dpi[13]!=96 or dpi[14]!=96 or dpi[7]!=dpi[8] or dpi[11]!=dpi[12] or theme[0]!=128 or theme[1]!=1 or theme[2] or theme[3]!=1 or theme[13] or not theme[16] or not theme[17]:raise RuntimeError('Control theme init/readback refused: '+json.dumps(report))
 for index in range(2):
  slot=theme[18+index];replacement=theme[22+index]
  if struct.unpack('<Q',boot.read(slot,8))[0]!=replacement:raise RuntimeError('Control theme import readback differs')
 ux=next(v for n,v in boot.modules().items() if n.endswith('\\uxtheme.dll'));app=struct.unpack('<Q',boot.read(ux+0x9cab8,8))[0]
 if not app or struct.unpack('<Q',boot.read(app+8,8))[0]!=theme[17]:raise RuntimeError('Process current theme provider changed')
 report['NativeCurrentUnchanged']=True
 return report
def prepare_control_theme10_probe(boot):
 if not boot.primary_suspended or not boot.entry_restored:raise RuntimeError('Probe preload requires own entry-held host')
 path=LAB/'BrowserProbe.dll';base=boot.load_library(path)
 boot._control_theme_probe=(path,base)
 return dict(PreparedOnly=True,Path=str(path),Base=hex(base),SHA256=sha(path))
def probe_control_theme10(boot,preflight=False,desktop_handle=None,desktop_name=None):
 if not preflight or boot.primary_suspended:raise RuntimeError('Only own preflight after primary resume is accepted')
 if not hasattr(boot,'_control_theme_probe'):raise RuntimeError('Own browser probe was not preloaded at entry')
 u=C.WinDLL('user32',use_last_error=True);u.GetUserObjectInformationW.argtypes=[C.c_void_p,C.c_int,C.c_void_p,W.DWORD,C.c_void_p];u.GetUserObjectInformationW.restype=W.BOOL
 name=C.create_unicode_buffer(256);needed=W.DWORD()
 okay=bool(desktop_handle and u.GetUserObjectInformationW(desktop_handle,2,name,C.sizeof(name),C.byref(needed)))
 if not okay or not desktop_name or name.value!=desktop_name or not name.value.startswith(('CodexVfsPreflight_','ControlThemeOwned-')):raise RuntimeError('Retained owned private desktop mismatch '+json.dumps(dict(Handle=desktop_handle,Expected=desktop_name,ReadName=name.value,WinError=C.get_last_error())))
 found=[];callback=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM);u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)];u.GetWindowThreadProcessId.restype=W.DWORD;u.EnumDesktopWindows.argtypes=[C.c_void_p,callback,W.LPARAM];u.EnumDesktopWindows.restype=W.BOOL
 @callback
 def owned(hwnd,param):
  pid=W.DWORD();u.GetWindowThreadProcessId(hwnd,C.byref(pid))
  if pid.value==boot.pi.pid:found.append(int(hwnd))
  return True
 if not u.EnumDesktopWindows(desktop_handle,owned,0) or not found:raise RuntimeError('No exact owned process windows on retained private desktop')
 path,base=boot._control_theme_probe
 if sha(path)!=next(x['SHA256'] for x in json.loads((LAB/'manifest.json').read_text())['Files'] if Path(x['Path'])==path):raise RuntimeError('Browser probe pin differs')
 root=LAB/'fixtures'/__import__('uuid').uuid4().hex;folder=root/'Folder';folder.mkdir(parents=True);(folder/'own.txt').write_text('Own integrated folder navigation item')
 folderBytes=str(folder.resolve()).encode('utf-16-le')+b'\0\0';desktopBytes=name.value.encode('utf-16-le')+b'\0\0'
 memory=boot.alloc(boot.pi.process,None,4096,0x3000,4);boot.patch(memory,struct.pack('<QQ',memory+16,memory+16+len(folderBytes))+folderBytes+desktopBytes)
 tid=W.DWORD();thread=boot.remote_thread(boot.pi.process,None,0,base+exports(path)['ControlBrowserProbeWorker'],memory,0,C.byref(tid));finished=False
 if not thread:raise C.WinError(C.get_last_error())
 try:
  if boot.wait(thread,20000)!=0:raise TimeoutError('Own browser worker timeout; exact-host abort required')
  finished=True;code=W.DWORD();fn=boot.k.GetExitCodeThread;fn.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];fn.restype=W.BOOL
  if not fn(thread,C.byref(code)):raise C.WinError(C.get_last_error())
  data=struct.unpack('<12I',boot.read(base+exports(path)['ControlBrowserState'],48));names=['Size','Version','Result','Complete','Thread','NavigationComplete','NavigationFailed','ItemCount','FolderMatched','DefViews','DirectUIViews','Reserved']
  workerDesktop=boot.read(base+exports(path)['ControlBrowserDesktop'],512).decode('utf-16-le').split('\0',1)[0]
  report=dict(OwnFolder=str(folder),PrivateDesktop=name.value,WorkerDesktop=workerDesktop,OwnedDesktopWindows=found,ThreadID=tid.value,Browser=dict(zip(names,data)),Code=code.value)
  if workerDesktop!=name.value:raise RuntimeError('Actual worker desktop differs '+json.dumps(report))
  if code.value or data[2] or data[3]!=1 or data[4]!=tid.value or not data[5] or data[6] or data[7]!=1 or not data[8] or not data[9] or not data[10]:raise RuntimeError('Integrated actual folder navigation failed '+json.dumps(report))
  report['Passed']=True;return report
 finally:
  boot.close(thread)
  if finished:boot.free(boot.pi.process,memory,0,0x8000)
