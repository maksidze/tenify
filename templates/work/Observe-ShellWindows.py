"""Read-only window state observer for the owned Explorer experiment.

No debugger, input hooks, keyboard state capture, titles, or UI interaction.
"""
import argparse, ctypes as C, json, time
from ctypes import wintypes as W
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('pid',type=int);p.add_argument('output',type=Path)
p.add_argument('--seconds',type=int,default=90);a=p.parse_args()
if not 1<=a.seconds<=180:raise ValueError('Bounded observation required')
k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32',use_last_error=True)
k.OpenProcess.restype=W.HANDLE;k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD]
k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)]
k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.CloseHandle.argtypes=[W.HANDLE]
k.CheckRemoteDebuggerPresent.argtypes=[W.HANDLE,C.POINTER(W.BOOL)]
callback=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
u.EnumWindows.argtypes=[callback,W.LPARAM];u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)]
u.GetClassNameW.argtypes=[W.HWND,W.LPWSTR,C.c_int];u.IsWindowVisible.argtypes=[W.HWND]
u.GetWindowRect.argtypes=[W.HWND,C.POINTER(W.RECT)]
handle=k.OpenProcess(0x101400,False,a.pid)
if not handle:raise C.WinError(C.get_last_error())
try:
 name=C.create_unicode_buffer(32768);length=W.DWORD(len(name))
 if not k.QueryFullProcessImageNameW(handle,0,name,C.byref(length)):raise C.WinError(C.get_last_error())
 expected=Path(__file__).resolve().parents[1]/'outputs/Windows10-Components/Runtime/Explorer10/explorer.exe'
 if name.value.casefold()!=str(expected).casefold():raise RuntimeError('Not the laboratory Explorer')
 with a.output.open('w',encoding='utf-8') as log:
  def emit(row):log.write(json.dumps({'time':time.time(),**row})+'\n');log.flush()
  debug=W.BOOL()
  if not k.CheckRemoteDebuggerPresent(handle,C.byref(debug)):raise C.WinError(C.get_last_error())
  emit({'event':'begin','pid':a.pid,'debuggerPresent':bool(debug.value),'seconds':a.seconds})
  before=None;deadline=time.monotonic()+a.seconds
  while time.monotonic()<deadline and k.WaitForSingleObject(handle,0)==258:
   rows=[]
   @callback
   def each(hwnd,param):
    owner=W.DWORD();u.GetWindowThreadProcessId(hwnd,C.byref(owner))
    if owner.value!=a.pid:return True
    cls=C.create_unicode_buffer(256);u.GetClassNameW(hwnd,cls,len(cls))
    if cls.value in ('tooltips_class32','WorkerW'):return True
    rect=W.RECT();u.GetWindowRect(hwnd,C.byref(rect))
    rows.append({'hwnd':hex(hwnd),'class':cls.value,'visible':bool(u.IsWindowVisible(hwnd)),
                 'rect':[rect.left,rect.top,rect.right,rect.bottom]})
    return True
   if not u.EnumWindows(each,0):raise C.WinError(C.get_last_error())
   rows.sort(key=lambda x:x['hwnd'])
   if rows!=before:emit({'event':'windows','windows':rows});before=rows
   time.sleep(.1)
  emit({'event':'end','processStillRunning':k.WaitForSingleObject(handle,0)==258})
finally:k.CloseHandle(handle)
