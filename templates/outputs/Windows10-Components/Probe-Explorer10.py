"""Probe an owned Explorer child on an invisible desktop; never stops the live shell."""
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import argparse,json,os,time,struct,subprocess,hashlib
parser=argparse.ArgumentParser();parser.add_argument('--exe',default=str(Path(__file__).parent/'Runtime/Explorer10/explorer.exe'));parser.add_argument('--arg',action='append',default=[]);parser.add_argument('--seconds',type=int,default=12);parser.add_argument('--output',default=str(Path(__file__).parent/'Metadata/explorer-isolated-probe.json'));parser.add_argument('--breakpoints');args=parser.parse_args()
kernel=C.WinDLL('kernel32',use_last_error=True);user=C.WinDLL('user32',use_last_error=True)
P=C.c_void_p;D=W.DWORD
def api(lib,name,result,types):
 f=getattr(lib,name);f.restype=result;f.argtypes=types;return f
class SI(C.Structure):
 _fields_=[('cb',D),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',D),('y',D),('xs',D),('ys',D),('xc',D),('yc',D),('fill',D),('flags',D),('show',W.WORD),('res2',W.WORD),('pres2',P),('hin',P),('hout',P),('herr',P)]
class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',D),('tid',D)]
class DE(C.Structure):_fields_=[('code',D),('pid',D),('tid',D),('pad',D),('data',C.c_ubyte*160)]
create=api(kernel,'CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,D,P,W.LPCWSTR,C.POINTER(SI),C.POINTER(PI)])
wait=api(kernel,'WaitForDebugEventEx',W.BOOL,[C.POINTER(DE),D]);cont=api(kernel,'ContinueDebugEvent',W.BOOL,[D,D,D])
close=api(kernel,'CloseHandle',W.BOOL,[P]);term=api(kernel,'TerminateProcess',W.BOOL,[P,D])
read=api(kernel,'ReadProcessMemory',W.BOOL,[P,P,P,C.c_size_t,C.POINTER(C.c_size_t)])
write=api(kernel,'WriteProcessMemory',W.BOOL,[P,P,P,C.c_size_t,C.POINTER(C.c_size_t)])
flush=api(kernel,'FlushInstructionCache',W.BOOL,[P,P,C.c_size_t])
threadOpen=api(kernel,'OpenThread',P,[D,W.BOOL,D]);contextGet=api(kernel,'GetThreadContext',W.BOOL,[P,P]);contextSet=api(kernel,'SetThreadContext',W.BOOL,[P,P])
path=api(kernel,'GetFinalPathNameByHandleW',D,[P,W.LPWSTR,D,D])
desktopCreate=api(user,'CreateDesktopW',P,[W.LPCWSTR,P,P,D,D,P]);desktopClose=api(user,'CloseDesktop',W.BOOL,[P])
owner=api(user,'GetWindowThreadProcessId',D,[P,C.POINTER(D)]);cls=api(user,'GetClassNameW',C.c_int,[P,W.LPWSTR,C.c_int])
callbackType=C.WINFUNCTYPE(W.BOOL,P,P);enum=api(user,'EnumDesktopWindows',W.BOOL,[P,callbackType,P])
enumChildren=api(user,'EnumChildWindows',W.BOOL,[P,callbackType,P])
sendText=api(user,'SendMessageTimeoutW',P,[P,W.UINT,C.c_size_t,P,W.UINT,W.UINT,C.POINTER(C.c_size_t)])
events=[];modules=[];windows=[];handles=set();result={'exe':str(Path(args.exe).resolve()),'liveShellStopped':False,'systemFilesModified':False};pi=PI();desk=None
breakpointConfigs=json.loads(Path(args.breakpoints).read_text(encoding='utf-8')) if args.breakpoints else []
breakpoints={}
for config in breakpointConfigs:
 if hashlib.sha256(Path(config['path']).read_bytes()).hexdigest()!=config['sha256']:raise RuntimeError('Breakpoint module hash mismatch')
 for point in config['points']:
  for capture in point.get('captures',[]):
   if hashlib.sha256(Path(capture['path']).read_bytes()).hexdigest()!=capture['sha256']:raise RuntimeError('Capture module hash mismatch')
def mem(addr,length):
 b=C.create_string_buffer(min(length,65536));n=C.c_size_t()
 if read(pi.process,addr,b,len(b),C.byref(n)):return b.raw[:n.value]
 return b''
def snapshot():
 found=[]
 def describe(h):
  name=C.create_unicode_buffer(256);cls(h,name,256)
  title=C.create_unicode_buffer(1024);n=C.c_size_t();sendText(h,13,1024,C.cast(title,P),2,150,C.byref(n))
  return {'class':name.value,'handle':hex(h),'pid':pi.pid,'text':title.value}
 @callbackType
 def child(h,p):
  pid=D();owner(h,C.byref(pid))
  if pid.value==pi.pid and len(found)<80:found.append(describe(h))
  return True
 @callbackType
 def cb(h,p):
  pid=D();owner(h,C.byref(pid))
  if pid.value==pi.pid:
   found.append(describe(h))
   if found[-1]['class']=='#32770':enumChildren(h,child,None)
  return True
 enum(desk,cb,None);return found
try:
 name='CodexExplorerProbe_'+str(os.getpid());desk=desktopCreate(name,None,None,0,0x1ff,None)
 if not desk:raise C.WinError(C.get_last_error())
 si=SI();si.cb=C.sizeof(si);si.desktop='WinSta0\\'+name
 exe=result['exe'];ok=create(exe,C.create_unicode_buffer(subprocess.list2cmdline([exe]+args.arg)),None,None,False,2,None,str(Path(exe).parent),C.byref(si),C.byref(pi))
 if not ok:raise C.WinError(C.get_last_error())
 result.update(created=True,pid=pi.pid,desktop=si.desktop)
 handles.update([pi.process,pi.thread]);deadline=time.monotonic()+args.seconds;exited=False
 while time.monotonic()<deadline:
  e=DE()
  if not wait(C.byref(e),150):continue
  data=bytes(e.data);status=0x10002
  try:
   if e.code==3:
    hfile,hprocess,hthread,base=struct.unpack_from('<QQQQ',data);handles.update([hprocess,hthread])
    if hfile:close(hfile)
   elif e.code==2:handles.add(struct.unpack_from('<Q',data)[0])
   elif e.code==6:
    hfile,base=struct.unpack_from('<QQ',data);name=C.create_unicode_buffer(2048)
    if hfile:path(hfile,name,2048,0);close(hfile)
    modules.append({'path':name.value,'base':hex(base)})
    for config in breakpointConfigs:
     if name.value.removeprefix('\\\\?\\').casefold()!=config['path'].casefold():continue
     for point in config['points']:
      address=base+point['rva'];original=mem(address,1)
      if original.hex()!=point['expectedByte']:raise RuntimeError('Breakpoint instruction mismatch')
      marker=C.create_string_buffer(b'\xcc');n=C.c_size_t()
      if not write(pi.process,address,marker,1,C.byref(n)) or n.value!=1:raise C.WinError(C.get_last_error())
      flush(pi.process,address,1);breakpoints[address]=(original,point)
   elif e.code==8:
    addr,isUnicode,length=struct.unpack_from('<QHH',data)
    msg=mem(addr,length*(2 if isUnicode else 1)).decode('utf-16-le' if isUnicode else 'cp1251',errors='replace').split('\0',1)[0]
    events.append({'type':'debugString','tid':e.tid,'message':msg})
   elif e.code==1:
    code=struct.unpack_from('<I',data)[0];first=struct.unpack_from('<I',data,152)[0]
    address=struct.unpack_from('<Q',data,16)[0]
    events.append({'type':'exception','code':hex(code),'address':hex(address),'firstChance':bool(first)})
    if code==0x80000003 and address in breakpoints:
     original,point=breakpoints.pop(address);b=C.create_string_buffer(original);n=C.c_size_t()
     if not write(pi.process,address,b,1,C.byref(n)) or n.value!=1:raise C.WinError(C.get_last_error())
     flush(pi.process,address,1)
     thread=threadOpen(0x58,False,e.tid)
     if not thread:raise C.WinError(C.get_last_error())
     try:
      buffer=C.create_string_buffer(1232+16);pointer=(C.addressof(buffer)+15)&~15
      C.c_uint32.from_address(pointer+48).value=0x100003
      if not contextGet(thread,pointer):raise C.WinError(C.get_last_error())
      ctx=C.string_at(pointer,1232)
      registers={name:hex(struct.unpack_from('<Q',ctx,offset)[0]) for name,offset in [('rax',120),('rcx',128),('rdx',136),('rsp',152),('r8',184),('r9',192),('rip',248)]}
      captures=[]
      for capture in point.get('captures',[]):
       module=next((m for m in modules if m['path'].removeprefix('\\\\?\\').casefold()==capture['path'].casefold()),None)
       if module:
        size=capture['size'];assert 0<size<=64
        captures.append({'label':capture['label'],'bytes':mem(int(module['base'],16)+capture['rva'],size).hex()})
      events.append({'type':'breakpointTrace','label':point['label'],'rva':hex(point['rva']),'registers':registers,'captures':captures})
      C.c_uint64.from_address(pointer+248).value=address
      if not contextSet(thread,pointer):raise C.WinError(C.get_last_error())
     finally:close(thread)
    if code!=0x80000003:status=0x80010001
   elif e.code==5:
    result['exitCode']=struct.unpack_from('<I',data)[0];exited=True
  finally:cont(e.pid,e.tid,status)
  if exited:break
 windows=snapshot();result['windowClasses']=sorted({w['class'] for w in windows});result['desktopAndTaskbarCreated']=all(c in result['windowClasses'] for c in ['Progman','Shell_TrayWnd'])
except Exception as e:result.update(created=False,error=str(e))
finally:
 if pi.process:
  term(pi.process,0)
  deadline=time.monotonic()+2
  while time.monotonic()<deadline:
   e=DE()
   if wait(C.byref(e),100):
    cont(e.pid,e.tid,0x10002)
    if e.code==5:break
 for h in handles:
  if h:close(h)
 if desk:desktopClose(desk)
 result.update(events=events,modules=modules,windows=windows)
 out=Path(args.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
 print(json.dumps({k:v for k,v in result.items() if k not in ['events','modules','windows']},ensure_ascii=False,indent=2))
