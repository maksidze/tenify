"""Only a newly created, owned, suspended signed Explorer child is modified."""
from pathlib import Path
import sys,shutil
base=Path('outputs/Windows10-Components').resolve();controller=base/'Probe-USVFS.py';lab=base/'Lab/ResourceCompat/Injected';lab.mkdir(parents=True,exist_ok=True)
shutil.copy2(base/'Runtime/Explorer10/explorer.exe',lab/'explorer.exe');shutil.copytree(base/'Runtime/Explorer10/ru-RU',lab/'ru-RU',dirs_exist_ok=True)
source=controller.read_text(encoding='utf-8-sig')
source=source.replace("out=base/'Metadata'/('usvfs-'+args.preset+'-probe.json')", "out=base/'Lab/ResourceCompat/Injected-probe.json'")
source=source.replace("exe=base/'Runtime/Explorer10/explorer.exe'", "exe=base/'Lab/ResourceCompat/Injected/explorer.exe'")
inject=r'''
  # The child was created suspended by this controller. Never attach to a supplied PID.
  import struct,sys
  sys.path.insert(0,str(Path('work/pylib').resolve()))
  import pefile
  alloc=api(kernel,'VirtualAllocEx',P,[P,P,C.c_size_t,D,D]);free=api(kernel,'VirtualFreeEx',W.BOOL,[P,P,C.c_size_t,D])
  write=api(kernel,'WriteProcessMemory',W.BOOL,[P,P,P,C.c_size_t,C.POINTER(C.c_size_t)])
  protect=api(kernel,'VirtualProtectEx',W.BOOL,[P,P,C.c_size_t,D,C.POINTER(D)])
  threadCreate=api(kernel,'CreateRemoteThread',P,[P,P,C.c_size_t,P,P,D,C.POINTER(D)])
  getProc=api(kernel,'GetProcAddress',P,[P,C.c_char_p]);getModule=api(kernel,'GetModuleHandleW',P,[W.LPCWSTR])
  def remoteModules():
   a=(P*2048)();n=D();entries={}
   if not enumModules(pi.process,a,C.sizeof(a),C.byref(n),3):raise C.WinError(C.get_last_error())
   for m in a[:min(n.value//C.sizeof(P),2048)]:
    b=C.create_unicode_buffer(4096);moduleName(pi.process,m,b,4096);entries[b.value.lower()]=m
   return entries
  shim=base/'Lab/ResourceCompat/FactoryWrapper/RSCW10.dll'
  before=remoteModules();kbase=getModule('kernelbase.dll');localStart=getProc(getModule('kernel32.dll'),b'LoadLibraryW')
  remoteKbase=next(v for k,v in before.items() if k.endswith('\\kernelbase.dll'))
  remoteStart=remoteKbase+(localStart-kbase)
  text=str(shim).encode('utf-16-le')+b'\0\0';buffer=C.create_string_buffer(text);address=alloc(pi.process,None,len(text),0x3000,4)
  if not address:raise C.WinError(C.get_last_error())
  remoteThread=None
  try:
   n=C.c_size_t()
   if not write(pi.process,address,buffer,len(text),C.byref(n)) or n.value!=len(text):raise C.WinError(C.get_last_error())
   tid=D();remoteThread=threadCreate(pi.process,None,0,remoteStart,address,0,C.byref(tid))
   if not remoteThread:raise C.WinError(C.get_last_error())
   deadline=time.monotonic()+10
   while wait(remoteThread,0)==258 and time.monotonic()<deadline:
    e=DE()
    if debugWait(C.byref(e),100):handleEvent(e)
   if wait(remoteThread,0)!=0:raise RuntimeError('Own-child helper load timeout')
  finally:
   if remoteThread:close(remoteThread)
   free(pi.process,address,0,0x8000)
  mods=remoteModules();shimBase=mods.get(str(shim).lower())
  if not shimBase:raise RuntimeError('Helper not loaded into owned child')
  exeBase=mods.get(str(exe).lower())
  if not exeBase:raise RuntimeError('Owned EXE module absent')
  pe=pefile.PE(str(exe));target=next(i.address-pe.OPTIONAL_HEADER.ImageBase for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports if i.name==b'RoGetActivationFactory')
  site=exeBase+target;oldProt=D()
  if not protect(pi.process,site,8,4,C.byref(oldProt)):raise C.WinError(C.get_last_error())
  try:
   value=C.create_string_buffer(struct.pack('<Q',shimBase+0x1000));n=C.c_size_t()
   if not write(pi.process,site,value,8,C.byref(n)) or n.value!=8:raise C.WinError(C.get_last_error())
  finally:
   ignored=D();protect(pi.process,site,8,oldProt.value,C.byref(ignored))
  result['ownedChildIATHook']={'pid':pi.pid,'iatRva':hex(target),'helper':str(shim),'signedExeOnDiskUnchanged':True}
'''
old=' if args.capture_debug:\n  if not debugAttach(pi.pid):raise C.WinError(C.get_last_error())\n  attached=True;debugKill(False);resume(pi.thread)'
prep=''' if args.capture_debug:
  if not debugAttach(pi.pid):raise C.WinError(C.get_last_error())
  attached=True;debugKill(False);resume(pi.thread)
  deadline=time.monotonic()+10;initial=False
  while time.monotonic()<deadline:
   e=DE()
   if debugWait(C.byref(e),100):
    if e.code==1 and int.from_bytes(bytes(e.data)[:4],'little')==0x80000003:initial=True
    handleEvent(e)
    if initial:break
  if not initial:raise RuntimeError('Initial loader breakpoint absent')
'''
source=source.replace(old,prep+inject)
sys.argv=[str(controller),'--preset','immersive-compat','--seconds','12','--capture-debug']
exec(compile(source,str(controller),'exec'),{'__file__':str(controller)})
