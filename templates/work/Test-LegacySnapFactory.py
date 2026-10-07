from pathlib import Path
import ctypes as C,json,sys,uuid
from ctypes import wintypes as W
root=Path(__file__).resolve().parent.parent;base=root/'outputs/Windows10-Components';lab=base/'Lab/LegacyClassFactoryCompat'
class GUID(C.Structure):_fields_=[('data',C.c_ubyte*16)]
def guid(text):return GUID.from_buffer_copy(uuid.UUID(text).bytes_le)
class CONFIG(C.Structure):_fields_=[('size',W.DWORD),('version',W.DWORD),('previous',C.c_void_p),('twinui',C.c_wchar*1024)]
ole=C.OleDLL('ole32');ole.CoInitializeEx.argtypes=[C.c_void_p,W.DWORD];ole.CoInitializeEx.restype=C.c_int32
ole.CoInitializeEx(None,2)
helper=C.WinDLL(str(lab/'LegacyClassFactoryCompat.dll'))
config=CONFIG.in_dll(helper,'LegacyFactoryConfig');config.previous=C.cast(ole.CoCreateInstance,C.c_void_p).value;config.twinui=str(base/'Image/4/Windows/System32/twinui.dll')
fn=helper.LegacyCoCreateInstance;fn.argtypes=[C.POINTER(GUID),C.c_void_p,W.DWORD,C.POINTER(GUID),C.POINTER(C.c_void_p)];fn.restype=C.c_int32
cls=guid('19227dc0-fc88-4aaa-8c2d-a0db913aa2ff');iid=guid('5fefbb8e-82c3-4ec4-93a0-05c4b9fcd4cd');ptr=C.c_void_p()
hr=fn(C.byref(cls),None,0x401,C.byref(iid),C.byref(ptr));report={'adapterResult':hex(hr&0xffffffff),'interface':hex(ptr.value or 0),'configSize':C.sizeof(CONFIG),'noGlobalRegistration':True}
if ptr.value:
 vt=C.cast(ptr,C.POINTER(C.POINTER(C.c_void_p))).contents
 query=C.WINFUNCTYPE(C.c_int32,C.c_void_p,C.POINTER(GUID),C.POINTER(C.c_void_p))(vt[0]);release=C.WINFUNCTYPE(W.ULONG,C.c_void_p)(vt[2])
 identity=C.c_void_p();unknown=guid('00000000-0000-0000-c000-000000000046');report['queryIUnknown']=hex(query(ptr,C.byref(unknown),C.byref(identity))&0xffffffff)
 if identity.value:C.WINFUNCTYPE(W.ULONG,C.c_void_p)(C.cast(identity,C.POINTER(C.POINTER(C.c_void_p))).contents[2])(identity)
 report['release']=release(ptr)
(lab/'own-snap-factory-test.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps(report));ole.CoUninitialize();sys.exit(0 if hr==0 else 1)
