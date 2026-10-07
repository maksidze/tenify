import ctypes as C,hashlib,json,sys,time,subprocess
from ctypes import wintypes as W
from pathlib import Path
lab=Path(__file__).resolve().parent;root=lab.parents[3];base=root/'outputs/Windows10-Components';sys.path[:0]=[str(base),str(root/'work/pylib')]
from ChildDiagnostics import ChildDiagnostics
import pefile
k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32')
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE;k.GetProcessTimes.argtypes=[W.HANDLE,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p];k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)];k.CheckRemoteDebuggerPresent.argtypes=[W.HANDLE,C.POINTER(W.BOOL)];k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.CloseHandle.argtypes=[W.HANDLE];u.GetShellWindow.restype=W.HWND;u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)]
h=k.OpenProcess(0x1fffff,False,1960);trace=None;process=None
try:
 times=[W.FILETIME() for i in range(4)];assert k.GetProcessTimes(h,*[C.byref(t) for t in times]);birth=(times[0].dwHighDateTime<<32)|times[0].dwLowDateTime;assert birth==134357001629709353
 owner=W.DWORD();u.GetWindowThreadProcessId(u.GetShellWindow(),C.byref(owner));assert owner.value==1960
 path=C.create_unicode_buffer(32768);size=W.DWORD(32768);assert k.QueryFullProcessImageNameW(h,0,path,C.byref(size));exe=base/'Runtime/Explorer10/explorer.exe';assert path.value.casefold()==str(exe).casefold();digest=hashlib.sha256(exe.read_bytes()).hexdigest();assert digest=='b059f455b37047f4e2b5eae01b21715e4baa304888ac31e44905b41ff6bbcbd0'
 pe=pefile.PE(str(exe));points=[]
 for rva,label in [(0x25fef0,'SetPreferenceEnter'),(0x25ff12,'SetPreferenceIncoming'),(0x25fff2,'LiveFindResult'),(0x260147,'PastFindResult'),(0x260179,'SetPreferenceReturn')]:
  p={'rva':rva,'label':label,'expectedByte':pe.get_data(rva,1).hex()}
  if rva in [0x25fef0,0x25ff12]:p['memory']=[{'register':'rdx','size':128}]
  points.append(p)
 trace=ChildDiagnostics(h,1960,lab/'preference-boundary-trace.jsonl',[{'path':str(exe),'sha256':digest,'points':points}]);trace.emit(type='exactOwnerGuard',pid=1960,birth=birth)
 out=(lab/'traced-operation.stdout').open('w');err=(lab/'traced-operation.stderr').open('w');process=subprocess.Popen([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(lab/'Set-NetworkVisibility.ps1'),'-Action','Promote'],creationflags=subprocess.CREATE_NO_WINDOW,stdout=out,stderr=err)
 end=time.monotonic()+20
 while time.monotonic()<end and k.WaitForSingleObject(h,0)==258:
  trace.pump(100)
  if process.poll() is not None and time.monotonic()>end-15:break
finally:
 if trace:trace.close()
 debug=W.BOOL(True);ok=k.CheckRemoteDebuggerPresent(h,C.byref(debug));(lab/'preference-trace-detach.json').write_text(json.dumps({'CheckSucceeded':bool(ok),'DebuggerPresent':bool(debug.value),'ExplorerPid':1960}));k.CloseHandle(h)
 if process:print('Own operation exit',process.wait(timeout=5));out.close();err.close()
