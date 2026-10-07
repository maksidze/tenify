"""Read-only geometry/module observation. No messages, input, screenshots or mutation."""
from pathlib import Path
import ctypes as C, json, winreg, struct, time
from ctypes import wintypes as W

root=Path(__file__).resolve().parent.parent
u=C.WinDLL('user32',use_last_error=True);k=C.WinDLL('kernel32',use_last_error=True);p=C.WinDLL('psapi',use_last_error=True)
P=C.c_void_p;D=W.DWORD;cb=C.WINFUNCTYPE(W.BOOL,P,P)
def api(lib,name,rest,args):
    f=getattr(lib,name);f.restype=rest;f.argtypes=args;return f
api(u,'EnumWindows',W.BOOL,[cb,P]);api(u,'EnumChildWindows',W.BOOL,[P,cb,P])
api(u,'GetClassNameW',C.c_int,[P,W.LPWSTR,C.c_int]);api(u,'GetWindowThreadProcessId',D,[P,C.POINTER(D)])
api(u,'GetWindowRect',W.BOOL,[P,C.POINTER(W.RECT)]);api(u,'IsWindowVisible',W.BOOL,[P])
api(u,'GetClassLongPtrW',C.c_size_t,[P,C.c_int]);api(u,'GetWindowLongPtrW',C.c_size_t,[P,C.c_int]);api(u,'GetParent',P,[P])
trays=[]
@cb
def top(hwnd,param):
    s=C.create_unicode_buffer(256);u.GetClassNameW(hwnd,s,256)
    if s.value=='Shell_TrayWnd':trays.append(hwnd)
    return True
if not u.EnumWindows(top,None):raise C.WinError(C.get_last_error())
result={'time':time.time(),'readOnly':True,'noMessagesOrInput':True,'trays':[]}
for tray in trays:
    owner=D();u.GetWindowThreadProcessId(tray,C.byref(owner))
    h=api(k,'OpenProcess',P,[D,W.BOOL,D])(0x410,False,owner.value);mods=[]
    if h:
        try:
            arr=(P*1024)();n=D()
            if api(p,'EnumProcessModulesEx',W.BOOL,[P,P,D,C.POINTER(D),D])(h,arr,C.sizeof(arr),C.byref(n),3):
                class MI(C.Structure):_fields_=[('base',P),('size',D),('entry',P)]
                for address in arr[:min(1024,n.value//C.sizeof(P))]:
                    name=C.create_unicode_buffer(32768);mi=MI()
                    api(p,'GetModuleFileNameExW',D,[P,P,W.LPWSTR,D])(h,address,name,len(name))
                    api(p,'GetModuleInformation',W.BOOL,[P,P,C.POINTER(MI),D])(h,address,C.byref(mi),C.sizeof(mi))
                    mods.append({'path':name.value,'base':int(address),'size':mi.size})
        finally:api(k,'CloseHandle',W.BOOL,[P])(h)
    def locate(value):
        for module in mods:
            if module['base']<=value<module['base']+module['size']:return {'path':module['path'],'rva':hex(value-module['base'])}
        return None
    windows=[]
    def record(hwnd):
        name=C.create_unicode_buffer(256);u.GetClassNameW(hwnd,name,256)
        rect=W.RECT();u.GetWindowRect(hwnd,C.byref(rect));pid=D();tid=u.GetWindowThreadProcessId(hwnd,C.byref(pid))
        windows.append({'hwnd':hex(hwnd),'class':name.value,'pid':pid.value,'tid':tid,'parent':hex(u.GetParent(hwnd) or 0),'visible':bool(u.IsWindowVisible(hwnd)),'rect':[rect.left,rect.top,rect.right,rect.bottom],'style':hex(u.GetWindowLongPtrW(hwnd,-16)),'exstyle':hex(u.GetWindowLongPtrW(hwnd,-20)),'classModule':locate(u.GetClassLongPtrW(hwnd,-16)),'classProc':locate(u.GetClassLongPtrW(hwnd,-24)),'wndProc':locate(u.GetWindowLongPtrW(hwnd,-4)),'userData':hex(u.GetWindowLongPtrW(hwnd,-21))})
    record(tray)
    @cb
    def child(hwnd,param):record(hwnd);return True
    u.EnumChildWindows(tray,child,None)
    result['trays'].append({'pid':owner.value,'windows':windows,'modules':mods})
for key in ['StuckRects3','MMStuckRects3']:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\'+key) as reg:
            values={}
            for i in range(winreg.QueryInfoKey(reg)[1]):
                name,data,kind=winreg.EnumValue(reg,i)
                values[name]={'type':kind,'hex':data.hex(),'dwords':list(struct.unpack('<'+'I'*(len(data)//4),data))} if isinstance(data,bytes) and len(data)%4==0 else {'type':kind,'data':data}
            result[key]=values
    except OSError as error:result[key]={'error':error.winerror}
output=root/'outputs/Windows10-Components/Metadata'/('language-indicator-geometry-'+str(int(result['time']))+'.json')
output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({'report':str(output),'trays':[{'pid':x['pid'],'windows':x['windows']} for x in result['trays']],'StuckRects3':result.get('StuckRects3')},ensure_ascii=False,indent=2))
