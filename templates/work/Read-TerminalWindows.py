"""Read-only window metadata for diagnosing leftover terminal frames."""
import ctypes as C,json
from ctypes import wintypes as W
from pathlib import Path
u=C.WinDLL('user32',use_last_error=True)
cb=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
u.EnumWindows.argtypes=[cb,W.LPARAM];u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)]
u.GetClassNameW.argtypes=[W.HWND,W.LPWSTR,C.c_int];u.GetWindowTextW.argtypes=[W.HWND,W.LPWSTR,C.c_int]
u.IsWindowVisible.argtypes=[W.HWND];u.GetWindowRect.argtypes=[W.HWND,C.POINTER(W.RECT)]
rows=[]
@cb
def each(hwnd,param):
    pid=W.DWORD();u.GetWindowThreadProcessId(hwnd,C.byref(pid))
    cls=C.create_unicode_buffer(256);u.GetClassNameW(hwnd,cls,256)
    if cls.value not in ('ConsoleWindowClass','CASCADIA_HOSTING_WINDOW_CLASS','PseudoConsoleWindow','Windows.UI.Core.CoreWindow','ApplicationFrameWindow') and pid.value!=9392:return True
    title=C.create_unicode_buffer(1024);u.GetWindowTextW(hwnd,title,1024)
    rect=W.RECT();u.GetWindowRect(hwnd,C.byref(rect))
    rows.append({'hwnd':hex(hwnd),'pid':pid.value,'class':cls.value,'title':title.value,'visible':bool(u.IsWindowVisible(hwnd)),'rect':[rect.left,rect.top,rect.right,rect.bottom]})
    return True
if not u.EnumWindows(each,0):raise C.WinError(C.get_last_error())
result={'windows':rows,'visible':sum(r['visible'] for r in rows)}
Path(__file__).with_name('terminal-window-inventory.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(result,ensure_ascii=False,indent=2))
