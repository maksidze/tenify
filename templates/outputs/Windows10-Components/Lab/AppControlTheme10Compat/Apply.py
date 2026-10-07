"""Apply private Win32 control resources to one explicitly selected existing x64 app."""
from pathlib import Path
import ctypes as C,struct,json,hashlib,sys,time
from ctypes import wintypes as W
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1]
sys.path.insert(0,str(BASE.parents[1]/'work/pylib'));import pefile
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
k=C.WinDLL('kernel32',use_last_error=True);ps=C.WinDLL('psapi',use_last_error=True)
def bind(lib,name,result,args):
 f=getattr(lib,name);f.restype=result;f.argtypes=args;return f
P=C.c_void_p;D=W.DWORD
openp=bind(k,'OpenProcess',P,[D,W.BOOL,D]);close=bind(k,'CloseHandle',W.BOOL,[P]);wait=bind(k,'WaitForSingleObject',D,[P,D]);times=bind(k,'GetProcessTimes',W.BOOL,[P,P,P,P,P]);query=bind(k,'QueryFullProcessImageNameW',W.BOOL,[P,D,W.LPWSTR,C.POINTER(D)])
readfn=bind(k,'ReadProcessMemory',W.BOOL,[P,P,P,C.c_size_t,C.POINTER(C.c_size_t)]);writefn=bind(k,'WriteProcessMemory',W.BOOL,[P,P,P,C.c_size_t,C.POINTER(C.c_size_t)]);alloc=bind(k,'VirtualAllocEx',P,[P,P,C.c_size_t,D,D]);free=bind(k,'VirtualFreeEx',W.BOOL,[P,P,C.c_size_t,D]);thread=bind(k,'CreateRemoteThread',P,[P,P,C.c_size_t,P,P,D,P]);getexit=bind(k,'GetExitCodeThread',W.BOOL,[P,C.POINTER(D)]);enum=bind(ps,'EnumProcessModulesEx',W.BOOL,[P,P,D,C.POINTER(D),D]);name=bind(ps,'GetModuleFileNameExW',D,[P,P,W.LPWSTR,D]);localmod=bind(k,'GetModuleHandleW',P,[W.LPCWSTR]);localproc=bind(k,'GetProcAddress',P,[P,C.c_char_p]);wow=bind(k,'IsWow64Process2',W.BOOL,[P,C.POINTER(W.WORD),C.POINTER(W.WORD)])
class Target:
 def __init__(self,cfg):
  self.h=openp(0x10143a,False,cfg['Pid'])
  if not self.h:raise C.WinError(C.get_last_error())
  self.pending=False
  if wait(self.h,0)!=258:raise RuntimeError('Selected target exited')
  born,end,kr,ur=(C.c_ulonglong()for _ in range(4));buf=C.create_unicode_buffer(32768);n=D(len(buf))
  if not times(self.h,C.byref(born),C.byref(end),C.byref(kr),C.byref(ur)) or born.value!=cfg['Birth']:raise RuntimeError('Selected target birth differs')
  if not query(self.h,0,buf,C.byref(n))or Path(buf.value).resolve()!=Path(cfg['Path']).resolve()or sha(buf.value)!=cfg['SHA256']:raise RuntimeError('Selected target file differs')
  a=W.WORD();b=W.WORD()
  if not wow(self.h,C.byref(a),C.byref(b))or a.value or b.value!=0x8664:raise RuntimeError('Only native x64 apps supported')
  debug=W.BOOL();fn=bind(k,'CheckRemoteDebuggerPresent',W.BOOL,[P,C.POINTER(W.BOOL)])
  if not fn(self.h,C.byref(debug))or debug.value:raise RuntimeError('Selected app debugger state differs')
 def modules(self):
  arr=(P*2048)();needed=D();out={}
  if not enum(self.h,arr,C.sizeof(arr),C.byref(needed),3):raise C.WinError(C.get_last_error())
  for v in arr[:min(needed.value//8,2048)]:
   b=C.create_unicode_buffer(32768);name(self.h,v,b,len(b));out[str(Path(b.value).resolve()).casefold()]=v
  return out
 def read(self,p,n):
  b=C.create_string_buffer(n);got=C.c_size_t()
  if not readfn(self.h,p,b,n,C.byref(got))or got.value!=n:raise C.WinError(C.get_last_error())
  return b.raw
 def put(self,data):
  p=alloc(self.h,None,len(data),0x3000,4);got=C.c_size_t();b=C.create_string_buffer(data)
  if not p or not writefn(self.h,p,b,len(data),C.byref(got))or got.value!=len(data):raise C.WinError(C.get_last_error())
  return p
 def call(self,fn,arg=0):
  h=thread(self.h,None,0,fn,arg,0,None)
  if not h:raise C.WinError(C.get_last_error())
  try:
   if wait(h,15000)!=0:self.pending=True;raise RuntimeError('Initializer pending: leave argument allocated; do not terminate user app')
   code=D()
   if not getexit(h,C.byref(code)):raise C.WinError(C.get_last_error())
   return code.value
  finally:close(h)
 def load(self,path):
  mods=self.modules()
  if any('usvfs' in n for n in mods):raise RuntimeError('Existing app contains VFS; refused')
  kb=str(Path('C:/Windows/System32/kernelbase.dll').resolve()).casefold()
  if kb not in mods:raise RuntimeError('Native KernelBase physical pathname differs')
  start=localproc(localmod('kernel32.dll'),b'LoadLibraryW')-localmod('kernelbase.dll')+mods[kb]
  data=self.put(str(path).encode('utf-16-le')+b'\0\0')
  try:self.call(start,data)
  finally:
   if not self.pending:free(self.h,data,0,0x8000)
  found=self.modules().get(str(path.resolve()).casefold())
  if not found:raise RuntimeError('Private helper not loaded')
  return found

def apply(config):
 cfg=json.loads(Path(config).read_text(encoding='utf-8-sig'));manifest=json.loads((LAB/'manifest.json').read_text())
 for item in manifest['Files']:
  if sha(item['Path'])!=item['SHA256']:raise RuntimeError('App style dependency changed '+item['Path'])
 target=Target(cfg);helper=LAB/'AppControlTheme10.dll';pe=pefile.PE(str(helper));exp={e.name.decode():e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name};base=target.load(helper)
 path=str(Path(cfg['Path']).resolve()).encode('utf-16-le')+b'\0\0';arg=struct.pack('<II65536s65s3x',65612,1,path,cfg['SHA256'].encode());memory=target.put(arg)
 try:code=target.call(base+exp['ControlTheme10Initialize'],memory)
 finally:
  if not target.pending:free(target.h,memory,0,0x8000)
 state=struct.unpack('<16I8Q',target.read(base+exp['ControlTheme10State'],128));report=dict(Pid=cfg['Pid'],Birth=cfg['Birth'],Path=cfg['Path'],HelperSHA256=sha(helper),Initialize=code,Active=state[3],Opens=state[4],Button=state[8],Edit=state[9],Combo=state[10],OldFailed=state[11],SystemFilesModified=False,VFS=False)
 if code or state[0]!=128 or state[1]!=1 or state[3]!=1 or state[13]or not state[16]:raise RuntimeError('App style initialize refused '+json.dumps(report))
 for i in range(2):
  if struct.unpack('<Q',target.read(state[18+i],8))[0]!=state[22+i]or not base<=state[22+i]<base+pe.OPTIONAL_HEADER.SizeOfImage:raise RuntimeError('Actual app IAT publication differs')
 report['Refresh']=target.call(base+exp['AppThemeRefresh']);time.sleep(.6)
 report['ReadMetadata']=target.call(base+exp['AppThemeReadback']);visual=struct.unpack('<8I',target.read(base+exp['AppThemeVisualState'],32));state=struct.unpack('<16I8Q',target.read(base+exp['ControlTheme10State'],128));report.update(Controls=visual[2],RefreshQueued=visual[5],Errors=visual[6],Opens=state[4],Button=state[8],Edit=state[9],Combo=state[10],OldFailed=state[11],VisibleUIConfirmed=False)
 close(target.h);return report
if __name__=='__main__':
 cfg=Path(sys.argv[1]);out=cfg.with_suffix('.result.json')
 try:result=apply(cfg);result['Status']='applied'
 except Exception as e:result=dict(Status='failed',Error=str(e),VFS=False,SystemFilesModified=False)
 out.write_text(json.dumps(result,indent=2),encoding='utf-8')
