"""Read diagnostics only from the exact broker-owned Settings process."""
import ctypes as C,json,sys
from ctypes import wintypes as W
from pathlib import Path
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'work/pylib'))
import pefile
record=Path(sys.argv[1]);parts=record.stem.split('_');pid=int(parts[1]);birth=int(parts[2],16)
k=C.WinDLL('kernel32',use_last_error=True)
def api(name,result,args):
 f=getattr(k,name);f.restype=result;f.argtypes=args;return f
h=api('OpenProcess',W.HANDLE,[W.DWORD,W.BOOL,W.DWORD])(0x410,False,pid)
assert h,C.get_last_error()
try:
 times=[W.FILETIME() for _ in range(4)]
 assert api('GetProcessTimes',W.BOOL,[W.HANDLE]+[C.POINTER(W.FILETIME)]*4)(h,*[C.byref(x) for x in times])
 assert (times[0].dwHighDateTime<<32)|times[0].dwLowDateTime==birth
 path=C.create_unicode_buffer(32768);n=W.DWORD(len(path))
 assert api('QueryFullProcessImageNameW',W.BOOL,[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)])(h,0,path,C.byref(n))
 assert path.value.lower()==r'c:\windows\immersivecontrolpanel\systemsettings.exe'
 modules=(W.HMODULE*2048)();used=W.DWORD()
 assert api('K32EnumProcessModulesEx',W.BOOL,[W.HANDLE,C.POINTER(W.HMODULE),W.DWORD,C.POINTER(W.DWORD),W.DWORD])(h,modules,C.sizeof(modules),C.byref(used),3)
 rows={}
 for module in list(modules)[:used.value//C.sizeof(W.HMODULE)]:
  path=C.create_unicode_buffer(32768)
  api('K32GetModuleFileNameExW',W.DWORD,[W.HANDLE,W.HMODULE,W.LPWSTR,W.DWORD])(h,module,path,len(path))
  p=Path(path.value)
  if p.name not in ['SettingsContentCompat.dll','SettingsControlTextCompat.dll','SettingsPowerCompat.dll']:continue
  pe=pefile.PE(str(p));values={}
  for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
   name=(symbol.name or b'').decode()
   if name not in ['SettingsContentStage','SettingsContentResult','SettingsControlTextInstalled','SettingsControlTextNativeCalls','SettingsControlTextFallbackCalls','SettingsControlTextFailures','SettingsControlTextLastResult','PowerInstalled','PowerFallbackCalls','PowerNativeCalls','PowerLastResult']:continue
   value=W.DWORD();read=C.c_size_t()
   assert api('ReadProcessMemory',W.BOOL,[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)])(h,module+symbol.address,C.byref(value),4,C.byref(read)) and read.value==4
   values[name]=value.value
  rows[p.name]=values
 proof={'Pid':pid,'Birth':str(birth),'ReadOnly':True,'Counters':rows,'VisibleUIVerified':False}
 print(json.dumps(proof,indent=2))
 (record.parent/'content-counter-proof.json').write_text(json.dumps(proof,indent=2))
finally:api('CloseHandle',W.BOOL,[W.HANDLE])(h)
