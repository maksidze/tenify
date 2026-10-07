"""Close the specifically identified empty terminal host, retaining the shell."""
import ctypes as C,json,datetime
from ctypes import wintypes as W
from pathlib import Path
inventory=json.loads(Path(__file__).with_name('terminal-window-inventory.json').read_text(encoding='utf-8'))
windows=[r for r in inventory['windows'] if r['pid']==9392 and r['visible']]
if len(windows)!=15 or any(r['class']!='CASCADIA_HOSTING_WINDOW_CLASS' or r['title']!='Terminal' for r in windows):raise RuntimeError('Unexpected terminal inventory')
k=C.WinDLL('kernel32',use_last_error=True)
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
k.GetProcessTimes.argtypes=[W.HANDLE]+[C.POINTER(W.FILETIME)]*4
k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)]
k.TerminateProcess.argtypes=[W.HANDLE,W.UINT];k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.CloseHandle.argtypes=[W.HANDLE]
h=k.OpenProcess(0x101001,False,9392)
if not h:raise C.WinError(C.get_last_error())
try:
    times=[W.FILETIME() for _ in range(4)]
    if not k.GetProcessTimes(h,*[C.byref(t) for t in times]):raise C.WinError(C.get_last_error())
    born=(times[0].dwHighDateTime<<32)|times[0].dwLowDateTime
    date=datetime.datetime.fromtimestamp(born/1e7-11644473600,datetime.timezone.utc)
    expected=datetime.datetime(2026,10,5,11,5,44,719316,tzinfo=datetime.timezone.utc)
    if abs((date-expected).total_seconds())>.001:raise RuntimeError('Terminal PID reused')
    path=C.create_unicode_buffer(32768);size=W.DWORD(len(path))
    if not k.QueryFullProcessImageNameW(h,0,path,C.byref(size)):raise C.WinError(C.get_last_error())
    if path.value.casefold()!=r'C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.18.10301.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe'.casefold():raise RuntimeError('Unexpected terminal binary')
    if not k.TerminateProcess(h,0):raise C.WinError(C.get_last_error())
    wait=k.WaitForSingleObject(h,5000)
    result={'pid':9392,'birth':str(born),'path':path.value,'emptyFrames':len(windows),'waitResult':wait,'onlyIdentifiedTerminalHost':True,'shellTerminated':False}
    Path(__file__).with_name('terminal-cleanup-result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))
finally:k.CloseHandle(h)
