import ctypes as C,json,sys
from ctypes import wintypes as W
k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32',use_last_error=True)
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE;k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)];k.CloseHandle.argtypes=[W.HANDLE]
u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)];u.GetClassNameW.argtypes=[W.HWND,W.LPWSTR,C.c_int];u.GetWindowLongPtrW.argtypes=[W.HWND,C.c_int];u.GetWindowLongPtrW.restype=C.c_ssize_t
pid=int(sys.argv[1]);h=k.OpenProcess(0x1000,False,pid);buf=C.create_unicode_buffer(32768);n=W.DWORD(len(buf));ok=bool(h and k.QueryFullProcessImageNameW(h,0,buf,C.byref(n)));rows=[]
CB=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
@CB
def child(w,p):
 owner=W.DWORD();tid=u.GetWindowThreadProcessId(w,C.byref(owner));name=C.create_unicode_buffer(256);u.GetClassNameW(w,name,256)
 if owner.value==pid:rows.append(dict(HWND=hex(w),Class=name.value,Style=hex(u.GetWindowLongPtrW(w,-16)&0xffffffff),Thread=tid))
 return True
@CB
def top(w,p):
 owner=W.DWORD();u.GetWindowThreadProcessId(w,C.byref(owner))
 if owner.value==pid:child(w,0);u.EnumChildWindows(w,child,0)
 return True
u.EnumWindows(top,0)
if h:k.CloseHandle(h)
print(json.dumps(dict(Pid=pid,QueryPath=ok,Path=buf.value,Controls=rows),indent=2))
