import ctypes as C, struct, time, os, json, sys
from ctypes import wintypes as W
sys.stdout.reconfigure(errors='backslashreplace')
k=C.WinDLL('kernel32',use_last_error=True); u=C.WinDLL('user32',use_last_error=True)
def api(lib,name,rest,args):
 f=getattr(lib,name);f.restype=rest;f.argtypes=args;return f
ptr=C.c_void_p; dw=W.DWORD; sz=C.c_size_t
class SI(C.Structure):
 _fields_=[('cb',dw),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',dw),('y',dw),('xs',dw),('ys',dw),('xc',dw),('yc',dw),('fill',dw),('flags',dw),('show',W.WORD),('res2',W.WORD),('pres2',ptr),('hin',ptr),('hout',ptr),('herr',ptr)]
class PI(C.Structure):
 _fields_=[('process',ptr),('thread',ptr),('pid',dw),('tid',dw)]
class DE(C.Structure):
 _fields_=[('code',dw),('pid',dw),('tid',dw),('pad',dw),('data',C.c_ubyte*160)]
create=api(k,'CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,ptr,ptr,W.BOOL,dw,ptr,W.LPCWSTR,C.POINTER(SI),C.POINTER(PI)])
wait=api(k,'WaitForDebugEvent',W.BOOL,[C.POINTER(DE),dw]);cont=api(k,'ContinueDebugEvent',W.BOOL,[dw,dw,dw])
read=api(k,'ReadProcessMemory',W.BOOL,[ptr,ptr,ptr,sz,C.POINTER(sz)])
write=api(k,'WriteProcessMemory',W.BOOL,[ptr,ptr,ptr,sz,C.POINTER(sz)])
protect=api(k,'VirtualProtectEx',W.BOOL,[ptr,ptr,sz,dw,C.POINTER(dw)])
flush=api(k,'FlushInstructionCache',W.BOOL,[ptr,ptr,sz])
getctx=api(k,'GetThreadContext',W.BOOL,[ptr,ptr]);setctx=api(k,'SetThreadContext',W.BOOL,[ptr,ptr])
openth=api(k,'OpenThread',ptr,[dw,W.BOOL,dw]);close=api(k,'CloseHandle',W.BOOL,[ptr])
term=api(k,'TerminateProcess',W.BOOL,[ptr,dw]);brk=api(k,'DebugBreakProcess',W.BOOL,[ptr])
path=api(k,'GetFinalPathNameByHandleW',dw,[ptr,W.LPWSTR,dw,dw])
cd=api(u,'CreateDesktopW',ptr,[W.LPCWSTR,ptr,ptr,dw,dw,ptr]);closed=api(u,'CloseDesktop',W.BOOL,[ptr])
def log(*a):print(*a,flush=True)
exe=r'@WORKSPACE@\work\Explorer10-Unsigned\explorer.exe'
probe_resources='--probe-resources' in sys.argv
default_desktop='--default-desktop' in sys.argv
desk=cd('CodexExplorer10_'+str(os.getpid()),None,None,0,0x1ff,None)
if not desk:raise C.WinError(C.get_last_error())
si=SI();si.cb=C.sizeof(si);si.desktop='WinSta0\\CodexExplorer10_'+str(os.getpid());pi=PI()
if default_desktop:si.desktop='WinSta0\\Default'
args=' '.join(a for a in sys.argv[1:] if a not in ['--probe-resources','--default-desktop','--stop-system-shell'])
if not create(exe,C.create_unicode_buffer('"'+exe+'" '+args),None,None,False,2,None,os.path.dirname(exe),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
log('START',pi.pid,'desktop',si.desktop,'args',args)
bps={};pending={};modules={};threads={pi.tid:pi.thread};base=0
def mem(addr,n):
 b=C.create_string_buffer(n);got=sz()
 if not read(pi.process,addr,b,n,C.byref(got)):return b''
 return b.raw[:got.value]
def patch(addr,b):
 old=dw();protect(pi.process,addr,len(b),0x40,C.byref(old));done=sz()
 if not write(pi.process,addr,b,len(b),C.byref(done)):raise C.WinError(C.get_last_error())
 restore=dw();protect(pi.process,addr,len(b),old.value,C.byref(restore));flush(pi.process,addr,len(b))
def bp(addr,name):
 if addr not in bps:
  original=mem(addr,1)
  if original:bps[addr]=(original,name);patch(addr,b'\xcc')
def ctx(tid):
 h=threads.get(tid)
 if not h:h=openth(0x1fffff,False,tid);threads[tid]=h
 raw=C.create_string_buffer(1248);address=(C.addressof(raw)+15)&~15;C.memset(address,0,1232);C.c_uint32.from_address(address+48).value=0x10000b
 if not getctx(h,address):raise C.WinError(C.get_last_error())
 return raw,address,h
def reg(c,offset):return C.c_uint64.from_address(c+offset).value
def describe(addr):
 candidates=[b for b in modules if b<=addr]
 if not candidates:return hex(addr)
 b=max(candidates)
 if addr-b>0x4000000:return hex(addr)
 return modules[b]+'+'+hex(addr-b)
functions={0xaa63c:'Configuration',0xaa8dc:'RegisteredShell',0xaa950:'DesktopPresent',0x87568:'CreateDesktopAndTray',0x87628:'CTray.Init',0x878dc:'TrayUI.Create',0x2380cc:'WaitForRefs',0x966e4:'WaitSCM',0x75f58:'ResourceString'}
start=time.monotonic();interrupted=False
try:
 while time.monotonic()-start<22:
  event=DE()
  if not wait(C.byref(event),100):
   if time.monotonic()-start>14 and not interrupted:brk(pi.process);interrupted=True
   continue
  data=bytes(event.data);status=0x10002
  if event.code==3:
   hfile,hproc,hth,base=struct.unpack_from('<QQQQ',data)
   modules[base]='explorer10';log('IMAGE',hex(base));
   if hfile:close(hfile)
   for off,name in functions.items():bp(base+off,name)
   if '--stop-system-shell' in sys.argv:
    find=api(u,'FindWindowW',ptr,[W.LPCWSTR,W.LPCWSTR]);owner=api(u,'GetWindowThreadProcessId',dw,[ptr,C.POINTER(dw)]);openp=api(k,'OpenProcess',ptr,[dw,W.BOOL,dw]);waitone=api(k,'WaitForSingleObject',dw,[ptr,dw])
    shellid=dw();owner(find('Progman',None),C.byref(shellid))
    if shellid.value:
     shell=openp(0x100001,False,shellid.value);log('STOP_SYSTEM_SHELL',shellid.value);term(shell,0);waitone(shell,3000);close(shell)
  elif event.code==2:
   threads[event.tid]=struct.unpack_from('<Q',data)[0]
  elif event.code==6:
   hfile,dllbase=struct.unpack_from('<QQ',data);buf=C.create_unicode_buffer(1024)
   dllname='?'
   if hfile:
    path(hfile,buf,1024,0);dllname=buf.value;close(hfile)
   modules[dllbase]=dllname;log('DLL',hex(dllbase),dllname)
  elif event.code==1:
   exc=struct.unpack_from('<I',data)[0];addr=struct.unpack_from('<Q',data,16)[0];first=struct.unpack_from('<I',data,152)[0]
   if exc==0x80000003 and addr in bps:
    raw,c,h=ctx(event.tid);original,name=bps[addr];patch(addr,original);C.c_uint64.from_address(c+248).value=addr
    if name.startswith('RETURN '):
     log(name,'tid',event.tid,'rax',hex(reg(c,120)))
     if name=='RETURN Configuration':log('CONFIG_BYTES',mem(reg(c,120),8).hex())
     del bps[addr]
    else:
     ret=struct.unpack('<Q',mem(reg(c,152),8))[0];log('ENTER',name,'tid',event.tid,'ret',describe(ret),'rcx',hex(reg(c,128)))
     if name=='ResourceString':log('RESOURCE_ID',reg(c,184),'module',describe(reg(c,136)))
     bp(ret,'RETURN '+name)
     if name=='WaitForRefs':log('REFHOST',mem(reg(c,128),32).hex())
     C.c_uint32.from_address(c+68).value|=0x100;pending[event.tid]=addr
     if name=='ResourceString' and probe_resources:
      alloc=api(k,'VirtualAllocEx',ptr,[ptr,ptr,sz,dw,dw]);textbuf='Task View'.encode('utf-16-le')+b'\0\0';remote=alloc(pi.process,None,len(textbuf),0x3000,4);patch(remote,textbuf)
      C.c_uint64.from_address(c+136).value=remote;C.c_uint64.from_address(c+184).value=9;C.c_uint64.from_address(c+248).value=base+0x764f0
      log('PROBE_RESOURCE_REPLACEMENT',hex(remote))
    setctx(h,c)
   elif exc==0x80000004 and event.tid in pending:
    addr2=pending.pop(event.tid)
    if addr2 in bps:patch(addr2,b'\xcc')
   elif exc==0x80000003:
    log('BREAK',describe(addr),'tid',event.tid)
    if interrupted:
     for tid in list(threads):
      try:
       raw,c,h=ctx(tid);log('THREAD',tid,'RIP',describe(reg(c,248)),'RSP',hex(reg(c,152)))
       stack=mem(reg(c,152),512)
       frames=[describe(v[0]) for v in struct.iter_unpack('<Q',stack[:len(stack)//8*8]) if any(b<=v[0]<b+0x1000000 for b in modules)]
       log('STACK_CANDIDATES',frames)
      except Exception as e:log('THREAD_ERROR',tid,str(e))
     cont(event.pid,event.tid,status);break
   else:log('EXCEPTION',hex(exc),describe(addr),'first',first);status=0x80010001
  elif event.code==8:
   addr,unicode,length=struct.unpack_from('<QHH',data);raw=mem(addr,length*(2 if unicode else 1));log('DEBUG_STRING',raw.decode('utf-16-le' if unicode else 'utf-8',errors='replace'))
  elif event.code==5:log('EXIT',struct.unpack_from('<I',data)[0]);cont(event.pid,event.tid,status);break
  cont(event.pid,event.tid,status)
finally:
 term(pi.process,0);close(pi.process)
 for h in set(threads.values()):
  if h:close(h)
 closed(desk)
 log('CLEANUP_DONE')
