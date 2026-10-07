"""A non-inherited kill-on-close Job for a caller-created suspended child."""
import ctypes as C
from ctypes import wintypes as W

class ChildJob:
    def __init__(self,breakaway_children=False):
        self.k=C.WinDLL('kernel32',use_last_error=True)
        def api(name,r,a):
            f=getattr(self.k,name);f.restype=r;f.argtypes=a;return f
        self.close=api('CloseHandle',W.BOOL,[C.c_void_p])
        self.assign_api=api('AssignProcessToJobObject',W.BOOL,[C.c_void_p,C.c_void_p])
        self.terminate=api('TerminateJobObject',W.BOOL,[C.c_void_p,W.UINT])
        self.query=api('QueryInformationJobObject',W.BOOL,[C.c_void_p,C.c_int,C.c_void_p,W.DWORD,C.c_void_p])
        make=api('CreateJobObjectW',C.c_void_p,[C.c_void_p,W.LPCWSTR])
        info=api('SetInformationJobObject',W.BOOL,[C.c_void_p,C.c_int,C.c_void_p,W.DWORD])
        self.handle=make(None,None)
        if not self.handle:raise C.WinError(C.get_last_error())
        limits=C.create_string_buffer(144);C.c_uint32.from_buffer(limits,16).value=0x3000 if breakaway_children else 0x2000
        if not info(self.handle,9,limits,144):
            error=C.get_last_error();self.close(self.handle);self.handle=None;raise C.WinError(error)
    def assign(self,process):
        if not self.assign_api(self.handle,process):raise C.WinError(C.get_last_error())
    def create_suspended(self,exe,command,si,pi,cwd):
        # JOB_LIST makes assignment atomic with creation: no orphan gap if this
        # controller dies between CreateProcess and an ordinary Assign call.
        def api(name,r,a):
            f=getattr(self.k,name);f.restype=r;f.argtypes=a;return f
        P=C.c_void_p;D=W.DWORD
        init=api('InitializeProcThreadAttributeList',W.BOOL,[P,D,D,C.POINTER(C.c_size_t)])
        update=api('UpdateProcThreadAttribute',W.BOOL,[P,D,C.c_size_t,P,C.c_size_t,P,P])
        delete=api('DeleteProcThreadAttributeList',None,[P])
        create=api('CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,D,P,W.LPCWSTR,P,P])
        inside=api('IsProcessInJob',W.BOOL,[P,P,C.POINTER(W.BOOL)])
        class EX(C.Structure):_fields_=[('startup',type(si)),('attributes',P)]
        size=C.c_size_t();init(None,1,0,C.byref(size));memory=C.create_string_buffer(size.value)
        if not init(memory,1,0,C.byref(size)):raise C.WinError(C.get_last_error())
        try:
            jobs=(P*1)(self.handle)
            if not update(memory,0,0x2000d,jobs,C.sizeof(jobs),None,None):raise C.WinError(C.get_last_error())
            ex=EX();ex.startup=si;ex.startup.cb=C.sizeof(ex);ex.attributes=C.addressof(memory)
            if not create(str(exe),C.create_unicode_buffer(command),None,None,False,0x08080004,None,str(cwd),C.byref(ex),C.byref(pi)):raise C.WinError(C.get_last_error())
            yes=W.BOOL()
            if not inside(pi.process,self.handle,C.byref(yes)) or not yes.value:raise RuntimeError('Created suspended child is not in its exact job')
        finally:delete(memory)
    def shutdown(self):
        import time
        if not self.handle:return
        try:
            if not self.terminate(self.handle,0):raise C.WinError(C.get_last_error())
            until=time.monotonic()+5
            while True:
                info=C.create_string_buffer(48)
                if not self.query(self.handle,1,info,48,None):raise C.WinError(C.get_last_error())
                if C.c_uint32.from_buffer(info,40).value==0:return
                if time.monotonic()>until:raise RuntimeError('Owned job cleanup still pending')
                time.sleep(.02)
        finally:self.close(self.handle);self.handle=None
