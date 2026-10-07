from pathlib import Path
import sys,ctypes as C,json,uuid,hashlib,argparse
from ctypes import wintypes as W
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'work/pylib'))
import pefile
ap=argparse.ArgumentParser();ap.add_argument('--live',action='store_true');ap.add_argument('--refresh',action='store_true');args=ap.parse_args()
path=Path('C:/Windows/System32/twinui.dll');pe=pefile.PE(str(path))
metadata=json.loads((ROOT/'work/compat-research/host-twinui-base/symbols.json').read_text())
assert hashlib.sha256(path.read_bytes()).hexdigest()==metadata['sha256']
class GUID(C.Structure):_fields_=[('data',C.c_ubyte*16)]
def guid(s):return GUID.from_buffer_copy(uuid.UUID(s).bytes_le)
clsid=guid('a919ea73-490e-4d5c-9ba7-97cbc73119fe')
iid_string=str(uuid.UUID(bytes_le=pe.get_data(0x3fb098,16)))
assert iid_string.startswith('4214f6fa-')
iid=guid(iid_string);factory_iid=guid('00000001-0000-0000-c000-000000000046')
provider_iid=guid('6d5140c1-7436-11ce-8034-00aa006009fa')
P=C.c_void_p;HR=C.c_long
ole=C.OleDLL('ole32');ole.CoInitializeEx.argtypes=[P,W.DWORD];ole.CoInitializeEx.restype=HR
ole.CoCreateInstance.argtypes=[C.POINTER(GUID),P,W.DWORD,C.POINTER(GUID),C.POINTER(P)];ole.CoCreateInstance.restype=HR
def call(p,slot,result,types,*values):
    address=C.cast(p,C.POINTER(C.POINTER(P))).contents[slot]
    return C.WINFUNCTYPE(result,P,*types)(address)(p,*values)
def emit(**v):print(json.dumps(v),flush=True)
def release(p):
    if p:call(p,2,W.ULONG,[])
hr=ole.CoInitializeEx(None,0);assert hr>=0
p=P();f=P();provider=P();dll=None
try:
    emit(Stage='start',Mode='live' if args.live else 'own',IID=iid_string)
    if args.live:
        shell=guid('c2f03a33-21f5-47fa-b4bb-156362a2f239')
        hr=ole.CoCreateInstance(C.byref(shell),None,4,C.byref(provider_iid),C.byref(provider));emit(CoCreateImmersiveShell=f'{hr&0xffffffff:08x}')
        if hr<0:sys.exit(2)
        hr=call(provider,3,HR,[C.POINTER(GUID),C.POINTER(GUID),C.POINTER(P)],C.byref(clsid),C.byref(iid),C.byref(p));emit(QueryService=f'{hr&0xffffffff:08x}')
    else:
        dll=C.WinDLL(str(path));get=dll.DllGetClassObject;get.argtypes=[C.POINTER(GUID),C.POINTER(GUID),C.POINTER(P)];get.restype=HR
        hr=get(C.byref(clsid),C.byref(factory_iid),C.byref(f));emit(OwnFactory=f'{hr&0xffffffff:08x}')
        if hr<0:sys.exit(2)
        hr=call(f,3,HR,[P,C.POINTER(GUID),C.POINTER(P)],None,C.byref(iid),C.byref(p));emit(OwnCreate=f'{hr&0xffffffff:08x}')
    if hr<0 or not p:sys.exit(3)
    if not args.live:
        v=C.cast(p,C.POINTER(C.POINTER(P))).contents
        assert v[3]-dll._handle==0x2cb3a0 and v[4]-dll._handle==0x83e20
    def read():
        v=(C.c_uint32*3)(0xa55aa55a,0xeeeeeeee,0x55aa55aa)
        hr=call(p,4,HR,[W.UINT,P],11,C.byref(v,4))
        emit(GetBOOL=f'{hr&0xffffffff:08x}',Setting=11,Value=v[1],Canaries=(v[0]==0xa55aa55a and v[2]==0x55aa55aa))
        assert hr>=0 and v[0]==0xa55aa55a and v[2]==0x55aa55aa
    read()
    if args.refresh:
        hr=call(p,3,HR,[W.UINT],11);emit(OnSettingChanged=f'{hr&0xffffffff:08x}',Setting=11)
        read()
finally:
    release(p);release(f);release(provider);ole.CoUninitialize()
