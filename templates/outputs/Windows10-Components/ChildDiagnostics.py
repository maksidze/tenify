"""Debugger used only for the child created by our launcher; does not suppress errors."""
import ctypes as C, struct, json, time,hashlib
from ctypes import wintypes as W
P=C.c_void_p;D=W.DWORD
class DE(C.Structure):
    _fields_=[('code',D),('pid',D),('tid',D),('pad',D),('data',C.c_ubyte*160)]
class ChildDiagnostics:
    def __init__(self, process, pid, output,breakpoints=None):
        self.process,self.pid=process,pid
        self.log=open(output,'a',encoding='utf-8');self.handles=set();self.active=False;self.breakpointConfigs=breakpoints or [];self.breakpoints={};self.diagnosticPatches={}
        k=C.WinDLL('kernel32',use_last_error=True)
        def api(n,r,t):
            f=getattr(k,n);f.restype=r;f.argtypes=t;return f
        self.attach=api('DebugActiveProcess',W.BOOL,[D]);self.stop=api('DebugActiveProcessStop',W.BOOL,[D])
        self.kill=api('DebugSetProcessKillOnExit',W.BOOL,[W.BOOL]);self.wait=api('WaitForDebugEventEx',W.BOOL,[C.POINTER(DE),D])
        self.cont=api('ContinueDebugEvent',W.BOOL,[D,D,D]);self.closeHandle=api('CloseHandle',W.BOOL,[P])
        self.readmem=api('ReadProcessMemory',W.BOOL,[P,P,P,C.c_size_t,C.POINTER(C.c_size_t)])
        self.openThread=api('OpenThread',P,[D,W.BOOL,D]);self.context=api('GetThreadContext',W.BOOL,[P,P])
        self.setContext=api('SetThreadContext',W.BOOL,[P,P]);self.protect=api('VirtualProtectEx',W.BOOL,[P,P,C.c_size_t,D,C.POINTER(D)])
        self.write=api('WriteProcessMemory',W.BOOL,[P,P,P,C.c_size_t,C.POINTER(C.c_size_t)]);self.flush=api('FlushInstructionCache',W.BOOL,[P,P,C.c_size_t])
        self.filePath=api('GetFinalPathNameByHandleW',D,[P,W.LPWSTR,D,D])
        if not self.attach(pid):raise C.WinError(C.get_last_error())
        self.active=True;self.kill(False)
    def emit(self,**event):
        event['time']=time.time();self.log.write(json.dumps(event,ensure_ascii=False)+'\n');self.log.flush()
    def read(self,address,length):
        b=C.create_string_buffer(length);n=C.c_size_t();self.readmem(self.process,address,b,length,C.byref(n));return b.raw[:n.value]
    def exception_details(self,code,data):
        count=min(struct.unpack_from('<I',data,24)[0],15)
        parameters=list(struct.unpack_from('<'+'Q'*count,data,32)) if count else []
        result={'parameters':[hex(value) for value in parameters]}
        # OriginateError carries HRESULT, UTF-16 length and buffer. TransformError
        # adds the previous HRESULT. Read only a bounded diagnostic message.
        if code in (0x40080201,0x40080202):
            offset=1 if code==0x40080201 else 2
            if len(parameters)>=offset+2 and parameters[offset]<=65536:
                result['restrictedErrorText']=self.read(parameters[offset+1],min(parameters[offset],512)*2).decode('utf-16-le',errors='replace').rstrip('\0')
        if code==0xc000027b and len(parameters)>=2 and parameters[1]<=16:
            records=[]
            for index in range(parameters[1]):
                pointer=self.read(parameters[0]+8*index,8)
                if len(pointer)!=8:continue
                address=struct.unpack('<Q',pointer)[0];record=self.read(address,56)
                if len(record)!=56:continue
                raw=struct.unpack('<7Q',record);size=raw[0]&0xffffffff;signature=raw[0]>>32;form=(raw[1]>>32)&3
                item={'address':hex(address),'size':size,'signature':hex(signature),'result':hex(raw[1]&0xffffffff),'form':form}
                if size>=40 and signature in (0x53453031,0x53453032):
                    if form==1 and raw[3]&0xffffffff==8 and raw[3]>>32<=256:
                        stack=self.read(raw[4],(raw[3]>>32)*8)
                        item['stack']=[hex(struct.unpack_from('<Q',stack,i)[0]) for i in range(0,len(stack)-7,8)]
                    elif form==2:
                        item['text']=self.read(raw[2],1024).decode('utf-16-le',errors='replace').split('\0',1)[0]
                records.append(item)
            result['stowedExceptions']=records
        return result
    def patchByte(self,address,value):
        old=D()
        if not value or len(value)>32:raise ValueError('Diagnostic patch size outside bounded limit')
        if not self.protect(self.process,address,len(value),0x40,C.byref(old)):raise C.WinError(C.get_last_error())
        try:
            n=C.c_size_t();b=C.create_string_buffer(value)
            if not self.write(self.process,address,b,len(value),C.byref(n)) or n.value!=len(value):raise C.WinError(C.get_last_error())
            self.flush(self.process,address,len(value))
        finally:
            ignored=D();self.protect(self.process,address,len(value),old.value,C.byref(ignored))
    def pump(self,timeout=100):
        e=DE()
        if not self.active or not self.wait(C.byref(e),timeout):return False
        d=bytes(e.data);status=0x10002
        try:
            if e.pid!=self.pid:raise RuntimeError('Unexpected child debugger PID')
            if e.code==8:
                addr,uni,length=struct.unpack_from('<QHH',d);message=self.read(addr,min(65536,length*(2 if uni else 1))).decode('utf-16-le' if uni else 'cp1251',errors='replace').split('\0',1)[0]
                self.emit(type='debugString',tid=e.tid,message=message)
            elif e.code==1:
                code=struct.unpack_from('<I',d)[0];address=struct.unpack_from('<Q',d,16)[0]
                info={'type':'exception','tid':e.tid,'code':hex(code),'address':hex(address),'firstChance':bool(struct.unpack_from('<I',d,152)[0])}
                info.update(self.exception_details(code,d))
                if code!=0x80000003 or address in self.breakpoints:
                    if code!=0x80000003:status=0x80010001
                    h=self.openThread(0x18,False,e.tid)
                    if h:
                        try:
                            b=C.create_string_buffer(1248);align=(C.addressof(b)+15)&~15;C.c_uint32.from_address(align+48).value=0x100003
                            if self.context(h,align):
                                regs={n:struct.unpack_from('<Q',C.string_at(align,1232),o)[0] for n,o in [('rax',120),('rcx',128),('rdx',136),('rbx',144),('rsp',152),('rbp',160),('rsi',168),('rdi',176),('r8',184),('r9',192),('r10',200),('r11',208),('r12',216),('r13',224),('r14',232),('r15',240),('rip',248)]}
                                info['registers']={n:hex(v) for n,v in regs.items()};info['stackRaw']=self.read(regs['rsp'],2048).hex()
                                if code==0xc0000005 and regs['r14']>=0x10088:
                                    info['r14Minus88Record']=self.read(regs['r14']-0x88,0x200).hex()
                                if address in self.breakpoints:
                                    point=self.breakpoints.pop(address);self.patchByte(address,bytes.fromhex(point['expectedByte']))
                                    captures={}
                                    for capture in point.get('memory',[]):
                                        start=regs[capture['register']]+capture.get('offset',0)
                                        data=self.read(start,min(capture['size'],512))
                                        item={'address':hex(start),'data':data.hex()}
                                        if capture.get('dereference') and len(data)>=8:
                                            pointer=struct.unpack_from('<Q',data)[0]
                                            item['pointedAddress']=hex(pointer);item['pointedData']=self.read(pointer,16).hex()
                                        captures[capture['register']]=item
                                    if captures:info['memory']=captures
                                    C.c_uint64.from_address(align+248).value=address
                                    if not self.setContext(h,align):raise C.WinError(C.get_last_error())
                                    info.update(type='breakpoint',label=point['label']);info.pop('stackRaw',None)
                        finally:self.closeHandle(h)
                self.emit(**info)
            elif e.code in (3,6):
                hfile=struct.unpack_from('<Q',d)[0];base=struct.unpack_from('<Q',d,24 if e.code==3 else 8)[0];path=''
                if hfile:
                    b=C.create_unicode_buffer(4096);self.filePath(hfile,b,len(b),0);path=b.value;self.closeHandle(hfile)
                self.emit(type='module',base=hex(base),path=path)
                for config in self.breakpointConfigs:
                    if path.removeprefix('\\\\?\\').casefold()!=config['path'].casefold():continue
                    from pathlib import Path
                    if hashlib.sha256(Path(config['path']).read_bytes()).hexdigest()!=config['sha256']:raise RuntimeError('Trace DLL hash changed')
                    for patch in config.get('diagnosticPatches',[]):
                        address=base+patch['rva'];before=bytes.fromhex(patch['before']);after=bytes.fromhex(patch['after'])
                        if len(before)!=len(after) or self.read(address,len(before))!=before:raise RuntimeError('Diagnostic patch instruction changed')
                        self.diagnosticPatches[address]=before
                        self.patchByte(address,after)
                        self.emit(type='diagnosticPatch',rva=hex(patch['rva']),reason=patch['reason'])
                    for point in config['points']:
                        address=base+point['rva']
                        if self.read(address,1).hex()!=point['expectedByte']:raise RuntimeError('Trace instruction changed')
                        self.patchByte(address,b'\xcc');self.breakpoints[address]=point
                if e.code==3:self.handles.update(struct.unpack_from('<QQ',d,8))
            elif e.code==2:self.handles.add(struct.unpack_from('<Q',d)[0])
            elif e.code==5:self.emit(type='exit',code=struct.unpack_from('<I',d)[0])
        finally:self.cont(e.pid,e.tid,status)
        return True
    def close(self):
        for address,point in self.breakpoints.items():
            try:self.patchByte(address,bytes.fromhex(point['expectedByte']))
            except OSError:pass
        self.breakpoints.clear()
        for address,before in self.diagnosticPatches.items():
            try:self.patchByte(address,before)
            except OSError:pass
        self.diagnosticPatches.clear()
        if self.active:self.stop(self.pid);self.active=False
        for h in self.handles:
            if h and h!=self.process:self.closeHandle(h)
        self.log.close()
