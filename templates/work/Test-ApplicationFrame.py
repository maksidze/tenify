from pathlib import Path
import ctypes as C,uuid,json
root=Path(__file__).resolve().parent.parent;P=C.c_void_p;H=C.c_int32
def guid(s):return (C.c_ubyte*16).from_buffer_copy(uuid.UUID(s).bytes_le)
cls=guid('ddc05a5a-351a-4e06-8eaf-54ec1bc2dcea');iid=guid('d6defab3-dbb9-4413-8af9-554586fdff94');factoryiid=guid('00000001-0000-0000-c000-000000000046')
ole=C.OleDLL('ole32');ole.CoInitializeEx(None,0)
k=C.WinDLL('kernel32',use_last_error=True);k.LoadLibraryExW.argtypes=[C.c_wchar_p,P,C.c_uint32];k.LoadLibraryExW.restype=P;k.GetProcAddress.argtypes=[P,C.c_char_p];k.GetProcAddress.restype=P
def method(p,n,result,args):return C.WINFUNCTYPE(result,P,*args)(C.cast(p,C.POINTER(C.POINTER(P))).contents[n])
results=[]
for name,path in [('native',Path('C:/Windows/System32/ApplicationFrame.dll')),('old',root/'outputs/Windows10-Components/Image/4/Windows/System32/ApplicationFrame.dll')]:
 item={'variant':name,'path':str(path)};h=k.LoadLibraryExW(str(path),None,8)
 if not h:item['loadError']=C.get_last_error();results.append(item);continue
 get=C.WINFUNCTYPE(H,P,P,C.POINTER(P))(k.GetProcAddress(h,b'DllGetClassObject'));f=P();hr=get(cls,factoryiid,C.byref(f));item['factoryHr']=hex(hr&0xffffffff)
 if hr>=0:
  o=P();hr=method(f,3,H,[P,P,C.POINTER(P)])(f,None,iid,C.byref(o));item['interfaceHr']=hex(hr&0xffffffff)
  if o:method(o,2,C.c_uint32,[])(o)
  method(f,2,C.c_uint32,[])(f)
 results.append(item)
out=root/'outputs/Windows10-Components/Lab/ApplicationFrameCompat';out.mkdir(exist_ok=True)
(out/'interface-probe.json').write_text(json.dumps(results,indent=2),encoding='utf8');print(json.dumps(results))
