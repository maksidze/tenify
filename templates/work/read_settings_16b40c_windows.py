from pathlib import Path
import ctypes as C, ctypes.wintypes as W, json,struct
root=Path(__file__).resolve().parent.parent
prefix=root/'outputs/Windows10-Components/Lab/SettingsBrokerCompat/broker-settings-16b40c5c5f60'
magic,pid,birth=struct.unpack('<IIQ',Path(str(prefix)+'.log.claim').read_bytes());assert magic==0x53434c32 and pid==11948
k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32',use_last_error=True);d=C.WinDLL('dwmapi',use_last_error=True)
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
k.GetProcessTimes.argtypes=[W.HANDLE]+[C.POINTER(W.FILETIME)]*4;k.GetProcessTimes.restype=W.BOOL
k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
callback=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
u.EnumWindows.argtypes=[callback,W.LPARAM];u.EnumWindows.restype=W.BOOL
u.EnumChildWindows.argtypes=[W.HWND,callback,W.LPARAM];u.EnumChildWindows.restype=W.BOOL
u.EnumThreadWindows.argtypes=[W.DWORD,callback,W.LPARAM];u.EnumThreadWindows.restype=W.BOOL
u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)];u.GetWindowThreadProcessId.restype=W.DWORD
u.GetClassNameW.argtypes=[W.HWND,W.LPWSTR,C.c_int];u.GetClassNameW.restype=C.c_int
u.GetWindowRect.argtypes=[W.HWND,C.POINTER(W.RECT)];u.GetWindowRect.restype=W.BOOL
u.IsWindowVisible.argtypes=[W.HWND];u.IsWindowVisible.restype=W.BOOL
u.GetParent.argtypes=[W.HWND];u.GetParent.restype=W.HWND
d.DwmGetWindowAttribute.argtypes=[W.HWND,W.DWORD,W.LPVOID,W.DWORD];d.DwmGetWindowAttribute.restype=W.LONG
h=k.OpenProcess(0x1000,False,pid)
if not h:raise SystemExit('Owned Settings has exited; no other process inspected')
rows={}
try:
    times=[W.FILETIME() for _ in range(4)];assert k.GetProcessTimes(h,*[C.byref(t) for t in times])
    assert (times[0].dwHighDateTime<<32)|times[0].dwLowDateTime==birth
    def read(hwnd):
        owner=W.DWORD();tid=u.GetWindowThreadProcessId(hwnd,C.byref(owner));cls=C.create_unicode_buffer(256);u.GetClassNameW(hwnd,cls,256)
        rect=W.RECT();rect_ok=u.GetWindowRect(hwnd,C.byref(rect));cloaked=W.DWORD();ch=d.DwmGetWindowAttribute(hwnd,14,C.byref(cloaked),4)
        return {'hwnd':hex(hwnd),'pid':owner.value,'tid':tid,'class':cls.value,'visible':bool(u.IsWindowVisible(hwnd)),'cloaked':cloaked.value if ch>=0 else None,'rect':[rect.left,rect.top,rect.right,rect.bottom] if rect_ok else None,'parent':hex(u.GetParent(hwnd) or 0)}
    @callback
    def children(hwnd,param):
        row=read(hwnd)
        if row['pid']==pid:rows[hwnd]=row
        return True
    @callback
    def tops(hwnd,param):
        row=read(hwnd)
        if row['pid']==pid or row['class']=='ApplicationFrameWindow':rows[hwnd]=row
        u.EnumChildWindows(hwnd,children,0)
        return True
    u.EnumWindows(tops,0)
    events=[json.loads(x) for x in Path(str(prefix)+'.pss.jsonl').read_text().splitlines()]
    for e in events:
        if e.get('event')=='thread':u.EnumThreadWindows(e['tid'],children,0)
    # Preserve ancestry of own Settings windows without interacting with them.
    for hwnd in list(rows):
        if rows[hwnd]['pid']!=pid:continue
        parent=u.GetParent(hwnd);seen=set()
        while parent and parent not in seen:
            seen.add(parent);rows[parent]=read(parent);parent=u.GetParent(parent)
    report={'targetPid':pid,'birth':str(birth),'readOnly':True,'windows':list(rows.values())}
    Path(str(prefix)+'.windows-readonly.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))
finally:k.CloseHandle(h)
