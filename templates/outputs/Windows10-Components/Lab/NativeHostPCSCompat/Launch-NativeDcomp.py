"""Native signed PCS DComp selector; own entry-held child memory only. No VFS."""
from pathlib import Path
import ctypes as C,struct,hashlib,sys,uuid,importlib.util
from ctypes import wintypes as W
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1];WORK=BASE.parent.parent/'work'
sys.path.insert(0,str(WORK/'pylib'));import pefile
PCS=Path('C:/Windows/System32/twinui.pcshell.dll');SHA='b8d9382e2c4b5e7425b4d814eb757bd99ee3c51f21ca7354ac3c7b4c38c4beb9';PDB=WORK/'compat-research/host-twinui/twinui.pcshell.pdb';PDBSHA='0699cb3148a9496d2ab72bdf0cd3e22e6e105438ada5fe22eebb179ea2c9ce4b'
signatureSpec=importlib.util.spec_from_file_location('b013_signature_resolver',BASE/'Lab/SignatureCompat/Resolve.py')
signatureModule=importlib.util.module_from_spec(signatureSpec);signatureSpec.loader.exec_module(signatureModule)
import json
signatureProfile=json.loads((BASE/'Lab/SignatureCompat/profiles.json').read_text(encoding='utf-8'))[0]
resolvedSites=signatureModule.resolve(signatureProfile,Path(__import__('os').environ['WINDIR']))
CALL=resolvedSites['Call'];DCOMP=resolvedSites['DComp'];XAML=resolvedSites['Xaml']
ORIGINAL=pefile.PE(str(PCS),fast_load=True).get_data(CALL,5)
class THREADENTRY32(C.Structure):_fields_=[('size',W.DWORD),('usage',W.DWORD),('tid',W.DWORD),('pid',W.DWORD),('priority',C.c_long),('delta',C.c_long),('flags',W.DWORD)]
def check(path,sha):
 if hashlib.sha256(path.read_bytes()).hexdigest()!=sha:raise RuntimeError('Unsupported native PCS build '+str(path))
def threads(pid):
 k=C.WinDLL('kernel32',use_last_error=True);snap=k.CreateToolhelp32Snapshot;snap.restype=C.c_void_p;snap.argtypes=[W.DWORD,W.DWORD];first=k.Thread32First;next=k.Thread32Next
 for f in(first,next):f.restype=W.BOOL;f.argtypes=[C.c_void_p,C.POINTER(THREADENTRY32)]
 close=k.CloseHandle;close.argtypes=[C.c_void_p];s=snap(4,0)
 if not s or s==C.c_void_p(-1).value:raise C.WinError(C.get_last_error())
 try:
  e=THREADENTRY32();e.size=C.sizeof(e);rows=[];ok=first(s,C.byref(e))
  while ok:
   if e.pid==pid:rows.append(e.tid)
   ok=next(s,C.byref(e))
  return sorted(rows)
 finally:close(s)
class ThreadGuard:
 def __init__(self,b,forbidden):self.b=b;self.forbidden=forbidden;self.held=[];self.records=[]
 def __enter__(self):
  k=self.b.k;op=k.OpenThread;op.restype=C.c_void_p;op.argtypes=[W.DWORD,W.BOOL,W.DWORD];pidof=k.GetProcessIdOfThread;pidof.restype=W.DWORD;pidof.argtypes=[C.c_void_p];ids=threads(self.b.pi.pid)
  if self.b.pi.tid not in ids:raise RuntimeError('Owned primary absent')
  try:
   for tid in ids:
    h=op(0x2|0x8|0x40,False,tid)
    if not h:raise C.WinError(C.get_last_error())
    if pidof(h)!=self.b.pi.pid:self.b.close(h);raise RuntimeError("Thread handle not owned by target")
    prior=self.b.suspend(h)
    if prior==0xffffffff:self.b.close(h);raise C.WinError(C.get_last_error())
    self.held.append(h)
    if tid==self.b.pi.tid and prior<1:raise RuntimeError('Owned primary unexpectedly running')
    raw=C.create_string_buffer(1248+16);aligned=(C.addressof(raw)+15)&~15;C.memset(aligned,0,1248);C.c_uint32.from_address(aligned+0x30).value=0x100001
    if not self.b.get_context(h,aligned):raise C.WinError(C.get_last_error())
    rip=C.c_uint64.from_address(aligned+0xf8).value
    if any(start<=rip<end for start,end in self.forbidden):raise RuntimeError('Thread executing replacement region')
    self.records.append(dict(tid=tid,priorSuspendCount=prior,rip=hex(rip)))
   if threads(self.b.pi.pid)!=ids:raise RuntimeError('Owned thread set changed during guard')
   return self
  except BaseException:self.__exit__(None,None,None);raise
 def __exit__(self,*args):
  failures=[]
  for h in reversed(self.held):
   if self.b.resume(h)==0xffffffff:failures.append(C.get_last_error())
   self.b.close(h)
  self.held=[]
  if failures:raise RuntimeError('Owned thread guard resume failed '+str(failures))
def near(b,address):
 center=address&~0xffff
 for distance in range(0x100000,0x3000000,0x10000):
  for target in(center+distance,center-distance):
   page=b.alloc(b.pi.process,target,4096,0x3000,4)
   if page:return int(page)
 raise RuntimeError('Bounded near allocation unavailable')
def rel(source,target,op=b'\xe9'):
 value=target-source-5
 if not -(1<<31)<=value<(1<<31):raise RuntimeError('Branch exceeds rel32')
 return op+struct.pack('<i',value)
def install_native_dcomp_compat(b):
 if not b.primary_suspended or not b.entry_restored or b.attached:raise RuntimeError('Only owned entry-held debugger-detached bootstrap accepted')
 check(PCS,SHA);check(PDB,PDBSHA);pe=pefile.PE(str(PCS))
 if pe.get_data(CALL,5)!=ORIGINAL:raise RuntimeError('Native call byte drift')
 rsds=[]
 for item in pe.DIRECTORY_ENTRY_DEBUG:
  data=pe.get_data(item.struct.AddressOfRawData,item.struct.SizeOfData)
  if data[:4]==b'RSDS':rsds.append((str(uuid.UUID(bytes_le=data[4:20])),struct.unpack_from('<I',data,20)[0]))
 if rsds!=[('01e019df-9560-0cdc-17cc-1b4e93279255',1)]:raise RuntimeError('Native PDB identity drift')
 candidates=[(n,v) for n,v in b.modules().items() if n.lower().endswith('\\twinui.pcshell.dll')]
 if not candidates:b.load_library(PCS);candidates=[(n,v) for n,v in b.modules().items() if n.lower().endswith('\\twinui.pcshell.dll')]
 if len(candidates)!=1:raise RuntimeError('Exactly one native PCS required, duplicate refused')
 name,base=candidates[0];spec=importlib.util.spec_from_file_location('NativePcsPhysical',BASE/'Launch-TouchpadCompat.py');identity=importlib.util.module_from_spec(spec);spec.loader.exec_module(identity);physical=identity.mapped_file_identity(b,base,PCS)
 for rva in(CALL-16,DCOMP,XAML):
  if b.read(base+rva,32)!=pe.get_data(rva,32):raise RuntimeError('Native PCS guarded context altered '+hex(rva))
 page=0;published=False
 try:
  page=near(b,base+CALL);code=b'\x83\xfa\x01\x75\x05'+rel(page+5,base+DCOMP)+rel(page+10,base+XAML);b.patch(page,code)
  if b.read(page,len(code))!=code:raise RuntimeError('DComp dispatcher readback failed')
  prior=W.DWORD()
  if not b.protect(b.pi.process,page,4096,0x20,C.byref(prior)) or not b.flush(b.pi.process,page,4096):raise C.WinError(C.get_last_error())
  replacement=rel(base+CALL,page,b'\xe8')
  with ThreadGuard(b,[(base+CALL,base+CALL+5),(page,page+len(code))]) as guard:
   if b.read(base+CALL,5)!=ORIGINAL:raise RuntimeError('Call changed before publish')
   published=True;b.patch(base+CALL,replacement,True)
   if b.read(base+CALL,5)!=replacement:raise RuntimeError('Call publish readback failed')
  record=dict(Type='nativePCS-DComp-memorySelector',OwnedPid=b.pi.pid,OwnedExe=str(b.exe),NativePCSPath=str(PCS),NativePCSSHA256=SHA,PdbSHA256=PDBSHA,NativeBase=hex(base),Physical=physical,Reported=name,CallRVA=hex(CALL),Original=ORIGINAL.hex(),Replacement=replacement.hex(),Thunk=hex(page),ThunkBytes=code.hex(),OriginalXamlRVA=hex(XAML),AltTabDcompRVA=hex(DCOMP),Condition='edx==1',Threads=guard.records,NoVFS=True,NoDiskWrites=True)
  b.events.append(record);return record
 except BaseException:
  if published:
   try:
    with ThreadGuard(b,[(base+CALL,base+CALL+5),(page,page+15)]):b.patch(base+CALL,ORIGINAL,True)
   except BaseException:raise RuntimeError('DComp partial publish cleanup failed; terminate exact owned child, do not resume')
  if page:b.free(b.pi.process,page,0,0x8000)
  raise
