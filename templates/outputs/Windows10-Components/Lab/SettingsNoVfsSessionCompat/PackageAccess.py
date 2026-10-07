"""Grant RX only on a newly owned nonce runtime, never shared/system paths."""
import ctypes as C,json,subprocess
from ctypes import wintypes as W
from pathlib import Path
K=C.WinDLL('kernel32',use_last_error=True);P=C.c_void_p
def sid_for_package(family):
 u=C.WinDLL('userenv',use_last_error=True);f=u.DeriveAppContainerSidFromAppContainerName;f.argtypes=[W.LPCWSTR,C.POINTER(P)];f.restype=W.LONG
 sid=P();hr=f(family,C.byref(sid))
 if hr:raise RuntimeError('Derive package SID failed '+hex(hr&0xffffffff))
 a=C.WinDLL('advapi32',use_last_error=True);a.ConvertSidToStringSidW.argtypes=[P,C.POINTER(W.LPWSTR)];a.ConvertSidToStringSidW.restype=W.BOOL
 text=W.LPWSTR()
 try:
  if not a.ConvertSidToStringSidW(sid,C.byref(text)):raise C.WinError(C.get_last_error())
  value=text.value
 finally:
  K.LocalFree.argtypes=[P];K.LocalFree(text);a.FreeSid.argtypes=[P];a.FreeSid(sid)
 return value
def grant_private_runtime(directory,family):
 directory=Path(directory).resolve();lab=Path(__file__).resolve().parent
 # Only freshly owned pernonce trees; no generic file/ancestor permission API.
 if directory.parent not in [(lab/'sessions').resolve(),(lab/'fixtures').resolve()] or len(directory.name)!=32 or any(x not in '0123456789abcdef' for x in directory.name):raise RuntimeError('ACL path outside private nonce roots')
 sid=sid_for_package(family)
 result=subprocess.run(['C:/Windows/System32/icacls.exe',str(directory),'/grant','*'+sid+':(OI)(CI)(RX)'],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=15)
 if result.returncode:raise RuntimeError('Private RX ACL failed '+result.stderr.decode(errors='replace'))
 return dict(Path=str(directory),PackageFamilyName=family,SID=sid,OnlyPrivateTree=True,Permission='Inherited read+execute; no write')
