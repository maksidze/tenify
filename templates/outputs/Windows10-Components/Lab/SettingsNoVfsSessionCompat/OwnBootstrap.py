"""Own-child x64 bootstrap. Import only; never takes an arbitrary PID or launches a shell.

Caller MUST supply PROCESS_INFORMATION from its own CREATE_SUSPENDED child.
pause_at_entry() stops after static DLL initialization, outside loader lock.
install_resource_hook() preserves the signed Explorer image on disk.
finish(detach=True) detaches debugging and resumes a normal interactive process.
Caller remains responsible for terminating its own child on bootstrap failure.
"""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import struct, time

P=C.c_void_p;D=W.DWORD
class DebugEvent(C.Structure):
    _fields_=[('code',D),('pid',D),('tid',D),('pad',D),('data',C.c_ubyte*160)]
def bind(lib,name,restype,types):
    fn=getattr(lib,name);fn.restype=restype;fn.argtypes=types;return fn
def pe_layout(path):
    b=Path(path).read_bytes();nt=struct.unpack_from('<I',b,0x3c)[0]
    if b[:2]!=b'MZ' or b[nt:nt+4]!=b'PE\0\0':raise ValueError('Invalid PE')
    machine,sections=struct.unpack_from('<HH',b,nt+4);size=struct.unpack_from('<H',b,nt+20)[0];o=nt+24
    if machine!=0x8664 or struct.unpack_from('<H',b,o)[0]!=0x20b:raise ValueError('x64 PE required')
    sect=[]
    for i in range(sections):
        s=o+size+i*40;vs,rva,rawsize,raw=struct.unpack_from('<IIII',b,s+8);sect.append((rva,max(vs,rawsize),raw))
    def offset(rva):
        for start,n,raw in sect:
            if start<=rva<start+n:return raw+rva-start
        raise ValueError('Unmapped RVA '+hex(rva))
    def string(rva):
        start=offset(rva);return b[start:b.index(b'\0',start)].decode('ascii')
    imports=[];directory=struct.unpack_from('<I',b,o+120)[0]
    if directory:
        d=offset(directory)
        while any(b[d:d+20]):
            oft,_,_,name,iat=struct.unpack_from('<IIIII',b,d);dll=string(name);t=offset(oft or iat);index=0
            while True:
                v=struct.unpack_from('<Q',b,t+index*8)[0]
                if not v:break
                imports.append({'dll':dll,'name':None if v>>63 else string(v+2),'ordinal':v&0xffff if v>>63 else None,'iatRva':iat+index*8})
                index+=1
            d+=20
    return {'entryRva':struct.unpack_from('<I',b,o+16)[0],'imports':imports}

class OwnChildBootstrap:
    def __init__(self,pi,exe,event_observer=None):
        self.pi=pi;self.exe=Path(exe).resolve();self.layout=pe_layout(self.exe)
        self.events=[];self.observer=event_observer;self.attached=False;self.primary_suspended=False
        self.entry=None;self.entry_original=None;self.entry_restored=False;self.image_base=None
        self.debug_handles=set();self.logs=[]
        self.k=C.WinDLL('kernel32',use_last_error=True);self.ps=C.WinDLL('psapi',use_last_error=True)
        self.attach=bind(self.k,'DebugActiveProcess',W.BOOL,[D]);self.detach=bind(self.k,'DebugActiveProcessStop',W.BOOL,[D]);self.kill_on_exit=bind(self.k,'DebugSetProcessKillOnExit',W.BOOL,[W.BOOL])
        self.debug_wait=bind(self.k,'WaitForDebugEventEx',W.BOOL,[C.POINTER(DebugEvent),D]);self.continue_event=bind(self.k,'ContinueDebugEvent',W.BOOL,[D,D,D])
        self.read_memory=bind(self.k,'ReadProcessMemory',W.BOOL,[P,P,P,C.c_size_t,C.POINTER(C.c_size_t)])
        self.write_memory=bind(self.k,'WriteProcessMemory',W.BOOL,[P,P,P,C.c_size_t,C.POINTER(C.c_size_t)])
        self.protect=bind(self.k,'VirtualProtectEx',W.BOOL,[P,P,C.c_size_t,D,C.POINTER(D)]);self.flush=bind(self.k,'FlushInstructionCache',W.BOOL,[P,P,C.c_size_t])
        self.suspend=bind(self.k,'SuspendThread',D,[P]);self.resume=bind(self.k,'ResumeThread',D,[P]);self.get_context=bind(self.k,'GetThreadContext',W.BOOL,[P,P]);self.set_context=bind(self.k,'SetThreadContext',W.BOOL,[P,P])
        self.close=bind(self.k,'CloseHandle',W.BOOL,[P]);self.wait=bind(self.k,'WaitForSingleObject',D,[P,D]);self.alloc=bind(self.k,'VirtualAllocEx',P,[P,P,C.c_size_t,D,D]);self.free=bind(self.k,'VirtualFreeEx',W.BOOL,[P,P,C.c_size_t,D])
        self.remote_thread=bind(self.k,'CreateRemoteThread',P,[P,P,C.c_size_t,P,P,D,C.POINTER(D)]);self.local_module=bind(self.k,'GetModuleHandleW',P,[W.LPCWSTR]);self.local_proc=bind(self.k,'GetProcAddress',P,[P,C.c_char_p])
        self.enumerate_modules=bind(self.ps,'EnumProcessModulesEx',W.BOOL,[P,P,D,C.POINTER(D),D]);self.module_name=bind(self.ps,'GetModuleFileNameExW',D,[P,P,W.LPWSTR,D])
        self.query_image=bind(self.k,'QueryFullProcessImageNameW',W.BOOL,[P,D,W.LPWSTR,C.POINTER(D)])
        b=C.create_unicode_buffer(4096);n=D(4096)
        if not self.query_image(pi.process,0,b,C.byref(n)) or Path(b.value).resolve()!=self.exe:raise RuntimeError('Owned child EXE path mismatch')
    def read(self,address,size):
        b=C.create_string_buffer(size);n=C.c_size_t()
        if not self.read_memory(self.pi.process,address,b,size,C.byref(n)) or n.value!=size:raise C.WinError(C.get_last_error())
        return b.raw
    def patch(self,address,data,executable=False):
        old=D()
        if not self.protect(self.pi.process,address,len(data),0x40 if executable else 4,C.byref(old)):raise C.WinError(C.get_last_error())
        try:
            b=C.create_string_buffer(data);n=C.c_size_t()
            if not self.write_memory(self.pi.process,address,b,len(data),C.byref(n)) or n.value!=len(data):raise C.WinError(C.get_last_error())
            if executable and not self.flush(self.pi.process,address,len(data)):raise C.WinError(C.get_last_error())
        finally:
            ignored=D()
            if not self.protect(self.pi.process,address,len(data),old.value,C.byref(ignored)):raise C.WinError(C.get_last_error())
    def consume(self,e):
        d=bytes(e.data);status=0x10002;hit=False
        try:
            if e.code==3:
                file,process,thread,base=struct.unpack_from('<QQQQ',d)
                self.debug_handles.update([process,thread]);self.image_base=base
                if file:self.close(file)
                if self.entry is None:
                    self.entry=base+self.layout['entryRva'];self.entry_original=self.read(self.entry,1);self.patch(self.entry,b'\xcc',True)
            elif e.code==6:
                file=struct.unpack_from('<Q',d)[0]
                if file:self.close(file)
            elif e.code==2:self.debug_handles.add(struct.unpack_from('<Q',d)[0])
            elif e.code==8:
                address,unicode,length=struct.unpack_from('<QHH',d)
                try:msg=self.read(address,min(65536,length*(2 if unicode else 1))).decode('utf-16-le' if unicode else 'cp1251',errors='replace').split('\0',1)[0]
                except OSError:msg='<unreadable debug string>'
                self.logs.append(msg)
            elif e.code==1:
                code=struct.unpack_from('<I',d)[0];address=struct.unpack_from('<Q',d,16)[0]
                self.events.append({'exception':hex(code),'address':hex(address)})
                if code==0x80000003 and address==self.entry and e.tid==self.pi.tid:
                    self.patch(self.entry,self.entry_original,True);self.entry_restored=True
                    raw=C.create_string_buffer(1248);aligned=(C.addressof(raw)+15)&~15;C.memset(aligned,0,1232);C.c_uint32.from_address(aligned+48).value=0x10000b
                    if not self.get_context(self.pi.thread,aligned):raise C.WinError(C.get_last_error())
                    if C.c_uint64.from_address(aligned+248).value!=self.entry+1:raise RuntimeError('Entry breakpoint RIP mismatch')
                    C.c_uint64.from_address(aligned+248).value=self.entry
                    if not self.set_context(self.pi.thread,aligned):raise C.WinError(C.get_last_error())
                    if self.suspend(self.pi.thread)==0xffffffff:raise C.WinError(C.get_last_error())
                    self.primary_suspended=True;hit=True
                elif code!=0x80000003:status=0x80010001
            elif e.code==5:raise RuntimeError('Owned child exited during bootstrap')
            if self.observer:self.observer(e)
        finally:
            if not self.continue_event(e.pid,e.tid,status):raise C.WinError(C.get_last_error())
        return hit
    def pause_at_entry(self,timeout=15):
        if not self.attach(self.pi.pid):raise C.WinError(C.get_last_error())
        self.attached=True
        if not self.kill_on_exit(False):raise C.WinError(C.get_last_error())
        if self.resume(self.pi.thread)==0xffffffff:raise C.WinError(C.get_last_error())
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            e=DebugEvent()
            if self.debug_wait(C.byref(e),100) and self.consume(e):
                self.events.append({'pausedAtEntry':hex(self.entry),'staticDllInitializationComplete':True});return
        raise RuntimeError('Executable entrypoint breakpoint timeout')
    def modules(self):
        a=(P*2048)();n=D();out={}
        if not self.enumerate_modules(self.pi.process,a,C.sizeof(a),C.byref(n),3):raise C.WinError(C.get_last_error())
        for h in a[:min(n.value//C.sizeof(P),2048)]:
            b=C.create_unicode_buffer(4096);self.module_name(self.pi.process,h,b,4096);out[b.value.lower()]=h
        return out
    def load_library(self,path,timeout=15):
        if not self.primary_suspended:raise RuntimeError('Own child must be held at executable entrypoint')
        path=Path(path).resolve()
        if not path.is_file():raise FileNotFoundError(path)
        mods=self.modules();remote_kernel=next(v for n,v in mods.items() if n.endswith('\\kernelbase.dll'))
        local_start=self.local_proc(self.local_module('kernel32.dll'),b'LoadLibraryW');local_base=self.local_module('kernelbase.dll');start=remote_kernel+local_start-local_base
        data=str(path).encode('utf-16-le')+b'\0\0';memory=self.alloc(self.pi.process,None,len(data),0x3000,4)
        if not memory:raise C.WinError(C.get_last_error())
        thread=None
        try:
            b=C.create_string_buffer(data);n=C.c_size_t()
            if not self.write_memory(self.pi.process,memory,b,len(data),C.byref(n)) or n.value!=len(data):raise C.WinError(C.get_last_error())
            tid=D();thread=self.remote_thread(self.pi.process,None,0,start,memory,0,C.byref(tid))
            if not thread:raise C.WinError(C.get_last_error())
            deadline=time.monotonic()+timeout
            while self.wait(thread,0)==258 and time.monotonic()<deadline:
                e=DebugEvent()
                if self.debug_wait(C.byref(e),100):self.consume(e)
            if self.wait(thread,0)!=0:raise RuntimeError('Own-child LoadLibraryW timeout')
        finally:
            if thread:self.close(thread)
            self.free(self.pi.process,memory,0,0x8000)
        result=self.modules().get(str(path).lower())
        if not result:raise RuntimeError('Helper library did not load: '+str(path))
        self.events.append({'loadedHelper':str(path),'base':hex(result)});return result
    def patch_iat(self,rva,address):
        if not self.primary_suspended:raise RuntimeError('Own child is not paused at entry')
        valid={i['iatRva'] for i in self.layout['imports']}
        if rva not in valid:raise ValueError('Address is not an import slot of owned EXE')
        site=self.image_base+rva;before=struct.unpack('<Q',self.read(site,8))[0]
        self.patch(site,struct.pack('<Q',address));self.events.append({'iatRva':hex(rva),'original':hex(before),'replacement':hex(address)})
        return before
    def install_resource_hook(self,helper):
        module=self.load_library(helper);slot=next(i for i in self.layout['imports'] if i['name']=='RoGetActivationFactory')
        self.patch_iat(slot['iatRva'],module+0x1000)
    def resume_primary(self):
        if self.primary_suspended:
            if self.resume(self.pi.thread)==0xffffffff:raise C.WinError(C.get_last_error())
            self.primary_suspended=False
        self.events.append({'primaryResumed':True})
    def finish(self,detach=True,resume_primary=True):
        if not self.entry_restored:raise RuntimeError('Executable entry breakpoint was not restored')
        if detach and self.attached:
            if not self.detach(self.pi.pid):raise C.WinError(C.get_last_error())
            self.attached=False
            # CREATE_PROCESS/CREATE_THREAD event handles belong to Windows.
            # EXIT events and DebugActiveProcessStop close them automatically;
            # closing their cached numeric values can close a reused own handle.
            # hFile event handles and our PI/remote-thread handles are separate.
            self.debug_handles.clear()
        if resume_primary:self.resume_primary()
        self.events.append({'debugDetached':detach,'primaryResumed':resume_primary})

def prepare_resource_hook(pi,exe,helper):
    """Prepare owned child, detach bootstrap debugger, LEAVE primary suspended.

    Caller can attach ChildDiagnostics before calling returned.resume_primary().
    This avoids a gap in startup logs and avoids two concurrent debuggers.
    """
    boot=OwnChildBootstrap(pi,exe)
    boot.pause_at_entry();boot.install_resource_hook(helper)
    boot.finish(detach=True,resume_primary=False)
    return boot
