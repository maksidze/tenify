"""Read only monitor geometry, taskbar state and desktop owner; no input or capture."""
import ctypes as C, json
from ctypes import wintypes as W
from pathlib import Path
u=C.WinDLL('user32',use_last_error=True);s=C.WinDLL('shell32',use_last_error=True)
class MI(C.Structure):
    _fields_=[('cbSize',W.DWORD),('rcMonitor',W.RECT),('rcWork',W.RECT),('dwFlags',W.DWORD),('device',W.WCHAR*32)]
class ABD(C.Structure):
    _fields_=[('cbSize',W.DWORD),('hwnd',W.HWND),('callback',W.UINT),('edge',W.UINT),('rc',W.RECT),('param',W.LPARAM)]
callback=C.WINFUNCTYPE(W.BOOL,W.HANDLE,W.HDC,C.POINTER(W.RECT),W.LPARAM)
u.EnumDisplayMonitors.argtypes=[W.HDC,C.POINTER(W.RECT),callback,W.LPARAM]
u.GetMonitorInfoW.argtypes=[W.HANDLE,C.POINTER(MI)]
u.GetShellWindow.restype=W.HWND
u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)]
u.SetThreadDpiAwarenessContext.argtypes=[W.HANDLE];u.SetThreadDpiAwarenessContext.restype=W.HANDLE
s.SHAppBarMessage.argtypes=[W.DWORD,C.POINTER(ABD)];s.SHAppBarMessage.restype=C.c_size_t
prior=u.SetThreadDpiAwarenessContext(C.c_void_p(-4))
if not prior: raise C.WinError(C.get_last_error())
try:
    monitors=[]
    def rect(r):return [r.left,r.top,r.right,r.bottom]
    @callback
    def each(handle,hdc,r,param):
        mi=MI();mi.cbSize=C.sizeof(mi)
        if not u.GetMonitorInfoW(handle,C.byref(mi)): return False
        monitors.append({'handle':hex(handle),'device':mi.device,'monitor':rect(mi.rcMonitor),'work':rect(mi.rcWork),'primary':bool(mi.dwFlags&1)})
        return True
    if not u.EnumDisplayMonitors(None,None,each,0):raise C.WinError(C.get_last_error())
    owner=W.DWORD();shell=u.GetShellWindow();u.GetWindowThreadProcessId(shell,C.byref(owner))
    data=ABD();data.cbSize=C.sizeof(data)
    state=s.SHAppBarMessage(4,C.byref(data))
    result={'shellPid':owner.value,'taskbarState':state,'autoHide':bool(state&1),'monitors':monitors}
    Path(__file__).with_name('monitor-workareas-current.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
finally:u.SetThreadDpiAwarenessContext(prior)
