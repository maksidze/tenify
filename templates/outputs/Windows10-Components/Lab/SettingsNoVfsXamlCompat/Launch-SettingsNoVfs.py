"""Own native Settings entry-held loader/factory route. Import-only, no registry/VFS."""
from pathlib import Path
import ctypes as C,struct,json,hashlib,sys,importlib.util
from ctypes import wintypes as W
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1];sys.path.insert(0,str(BASE.parents[1]/'work/pylib'));import pefile

def module(path,name):s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
GUARD=module(BASE/'Lab/NativeHostPCSCompat/Launch-NativeDcomp.py','SettingsOwnThreadGuard')
IDENTITY=module(BASE/'Launch-TouchpadCompat.py','SettingsNativeMapped')
def hashcheck(path,sha):
 if hashlib.sha256(Path(path).read_bytes()).hexdigest()!=sha:raise RuntimeError('SettingsnoVFS dependency differs '+str(path))
def initialize_remote(b,path,export):
 base=b.load_library(path);mapped=IDENTITY.mapped_file_identity(b,base,Path(path));pe=pefile.PE(str(path));rva=next(x.address for x in pe.DIRECTORY_ENTRY_EXPORT.symbols if x.name and x.name.decode()==export);t=b.remote_thread(b.pi.process,None,0,base+rva,None,0,None)
 if not t:raise C.WinError(C.get_last_error())
 try:
  if b.wait(t,30000)!=0:raise RuntimeError('Settings initializer timeout; exactownedchild mustterminate')
  exitcode=W.DWORD();f=b.k.GetExitCodeThread;f.restype=W.BOOL;f.argtypes=[C.c_void_p,C.POINTER(W.DWORD)]
  if not f(t,C.byref(exitcode)):raise C.WinError(C.get_last_error())
  if exitcode.value:
   diagnostics={}
   for module_path, module_base in b.modules().items():
    if Path(module_path).name.lower() not in ['settingscontentcompat.dll','settingscaptioncompat.dll','settingssystemprofilecompat.dll']:continue
    module_pe=pefile.PE(module_path)
    for symbol in module_pe.DIRECTORY_ENTRY_EXPORT.symbols:
     if symbol.name and symbol.name.decode() in ['SettingsContentStage','SettingsCaptionStage','SettingsSystemProfileStage']:
      diagnostics[symbol.name.decode()]=struct.unpack('<i',b.read(module_base+symbol.address,4))[0]
   raise RuntimeError(export+' failed '+hex(exitcode.value)+' '+json.dumps(diagnostics))
  return dict(Base=hex(base),Physical=mapped,Result=exitcode.value)
 finally:b.close(t)
def install_settings_novfs(b,include_content=True):
 if b.attached or not b.primary_suspended or not b.entry_restored:raise RuntimeError('Settings requires ownentryheld detachedbootstrap')
 m=json.loads((LAB/'adapter-metadata.json').read_text())
 if b.exe.resolve()!=Path(m['NativeExe']).resolve():raise RuntimeError('WrongSettings targetrole')
 for name in ['NativeExe','OldMain','Selector','ContentHelper']:hashcheck(m[name],m[name+'SHA256' if name!='ContentHelper' else 'ContentSHA256'])
 pe=pefile.PE(m['NativeExe']);image=b.image_base or next(v for n,v in b.modules().items() if Path(n).resolve()==b.exe.resolve());rva=m['LEA_RVA'];original=bytes.fromhex(m['LEABytes'])
 if pe.get_data(rva,7)!=original or b.read(image+rva-16,32)!=pe.get_data(rva-16,32):raise RuntimeError('NativeSettings loaderinstruction/context changed')
 selector=initialize_remote(b,Path(m['Selector']),m['InitializeExport']);content=initialize_remote(b,Path(m['ContentHelper']),m['ContentInitialize']) if include_content else None
 # Native EXE's LoadLibraryExW(flags0) now receives a genuine privateabsolute DLL path.
 data=(m['OldMain']+'\0').encode('utf-16le');page=GUARD.near(b,image+rva);published=False
 try:
  b.patch(page,data);prior=W.DWORD()
  if not b.protect(b.pi.process,page,4096,2,C.byref(prior)):raise C.WinError(C.get_last_error())
  displacement=page-(image+rva+7)
  if not -(1<<31)<=displacement<(1<<31):raise RuntimeError('Settingspathdata outsideLEA range')
  replacement=original[:3]+struct.pack('<i',displacement)
  with GUARD.ThreadGuard(b,[(image+rva,image+rva+7)]) as guard:
   if b.read(image+rva,7)!=original:raise RuntimeError('Settingscall changedbeforepublish')
   published=True;b.patch(image+rva,replacement,True)
   if b.read(image+rva,7)!=replacement or b.read(page,len(data))!=data:raise RuntimeError('Settingsloaderreadback failed')
  report=dict(Type='Settings10NoVFS',OwnedPid=b.pi.pid,NativeExe=m['NativeExe'],NativeExeSHA256=m['NativeExeSHA256'],LoaderLEARVA=hex(rva),Before=original.hex(),After=replacement.hex(),PrivatePathData=hex(page),Selector=selector,Content=content,Threads=guard.records,NoVFS=True,NoSystemFiles=True)
  b.events.append(report);return report
 except BaseException:
  if published:
   with GUARD.ThreadGuard(b,[(image+rva,image+rva+7)]):b.patch(image+rva,original,True)
  b.free(b.pi.process,page,0,0x8000);raise
