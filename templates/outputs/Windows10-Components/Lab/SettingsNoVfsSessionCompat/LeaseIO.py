"""Atomic Windows lease IO; never caches or extends a lease on failed reads."""
import ctypes as C,os,time
from ctypes import wintypes as W
K=C.WinDLL('kernel32',use_last_error=True);P=C.c_void_p
create=K.CreateFileW;create.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,P,W.DWORD,W.DWORD,P];create.restype=P
read=K.ReadFile;read.argtypes=[P,P,W.DWORD,P,P];read.restype=W.BOOL
close=K.CloseHandle;close.argtypes=[P];close.restype=W.BOOL
TRANSIENT={2,3,5,32,33,303}
def read_lease(path):
 deadline=time.monotonic()+.25
 while True:
  h=create(str(path),0x80000000,7,None,3,0x80,None)
  if h!=P(-1).value:
   try:
    buffer=C.create_string_buffer(17);got=W.DWORD()
    if not read(h,buffer,17,C.byref(got),None):raise C.WinError(C.get_last_error())
    return buffer.raw[:got.value] # Caller rejects anything except exactly16.
   finally:close(h)
  error=C.get_last_error()
  if error not in TRANSIENT or time.monotonic()>=deadline:raise C.WinError(error)
  time.sleep(.01)
def replace_lease(temp,path):
 deadline=time.monotonic()+.25
 while True:
  try:os.replace(temp,path);return
  except OSError as e:
   if getattr(e,'winerror',None) not in {5,32,33,303} or time.monotonic()>=deadline:raise
   time.sleep(.01)
