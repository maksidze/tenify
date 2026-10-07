"""Explicit no-legacy-touchpad policy, own entry-paused child memory only.

Use the old component's existing ComponentEnabled=0 branch; never fabricate
successful PTP registration. Its obsolete API is replaced by FALSE/error50.
"""
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import hashlib,struct,sys
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'));import pefile
OLD_SHA='ad77f57da420eba9209764f8519d7a2a14043f75bd881d0c4008002537378460'
USER_SHA='d01c10963508ffd503ce9c789dfc3eb1dd63340df3899b695e7775ef46edd966'
STUB_SHA='e8a386b72ea53e3e465cae85f601c0001015a37ac2fd6133173a9e7aa4a65f8e'
BRANCH_RVA=0x76864;OLD_BRANCH=bytes.fromhex('0f898e7a0a00');DISABLED_RVA=0x11e303
DISABLED_BYTES=bytes.fromhex('33c0e91d86f5ff');IAT_RVA=0x4908e0
STUB_BYTES=bytes.fromhex('4883ec28b932000000ff15a941000031c04883c428c3')
class PointerDevice(C.Structure):
    _fields_=[('orientation',W.DWORD),('device',C.c_void_p),('type',C.c_int),('monitor',C.c_void_p),('startingCursorId',W.ULONG),('maxActiveContacts',W.USHORT),('product',W.WCHAR*520)]
def pointer_inventory():
    u=C.WinDLL('user32',use_last_error=True);f=u.GetPointerDevices
    f.restype=W.BOOL;f.argtypes=[C.POINTER(W.UINT),C.POINTER(PointerDevice)]
    n=W.UINT()
    if not f(C.byref(n),None):raise C.WinError(C.get_last_error())
    if n.value>256:raise RuntimeError('Pointer inventory exceeds bounded limit')
    rows=[]
    if n.value:
        a=(PointerDevice*n.value)()
        if not f(C.byref(n),a):raise C.WinError(C.get_last_error())
        rows=[{'type':x.type,'product':x.product,'maxActiveContacts':x.maxActiveContacts} for x in a[:n.value]]
    return rows
def checked(path,sha):
    if hashlib.sha256(path.read_bytes()).hexdigest()!=sha:raise RuntimeError('Unsupported binary build: '+str(path))
def mapped_file_identity(bootstrap,module,path):
    """Inspector runs outside child VFS: verify physical mapped image backing."""
    ps=C.WinDLL('psapi',use_last_error=True);k=C.WinDLL('kernel32',use_last_error=True)
    mapped=ps.GetMappedFileNameW;mapped.restype=W.DWORD;mapped.argtypes=[C.c_void_p,C.c_void_p,W.LPWSTR,W.DWORD]
    query=k.QueryDosDeviceW;query.restype=W.DWORD;query.argtypes=[W.LPCWSTR,W.LPWSTR,W.DWORD]
    actual=C.create_unicode_buffer(32768)
    if not mapped(bootstrap.pi.process,module,actual,len(actual)):raise C.WinError(C.get_last_error())
    expected=str(path.resolve());drive=expected[:2];device=C.create_unicode_buffer(32768)
    if len(drive)!=2 or drive[1]!=':' or not query(drive,device,len(device)):raise RuntimeError('Cannot resolve expected physical backing volume')
    ntExpected=device.value+expected[2:]
    if actual.value.casefold()!=ntExpected.casefold():raise RuntimeError('Mapped DLL physical backing mismatch: '+actual.value+' expected '+ntExpected)
    return {'physicalMappedFile':actual.value,'expectedPhysicalFile':ntExpected,'mappedIdentityMatched':True}
def install_touchpad_compat(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored or bootstrap.attached:
        raise RuntimeError('Touchpad policy requires newly owned entry-paused child with bootstrap debugger detached')
    inventory=pointer_inventory()
    if any(row['type']==4 for row in inventory):raise RuntimeError('Touchpad present; refusing legacy gesture opt-out')
    old=BASE/'Image/4/Windows/System32/twinui.dll';stub=BASE/'Lab/WindowGroupCompat/U32W10.dll'
    checked(old,OLD_SHA);checked(stub,STUB_SHA)
    modules=bootstrap.modules();native=[(n,b) for n,b in modules.items() if n.lower().endswith('\\user32.dll')]
    if len(native)!=1:raise RuntimeError('Exactly one native USER32 required')
    nativePath,nativeBase=native[0];checked(Path(nativePath),USER_SHA)
    pe=pefile.PE(str(nativePath));export=next(e for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.ordinal==2542)
    if export.name!=b'SetCoveredWindowStates' or export.address!=0x73ca0 or export.forwarder:raise RuntimeError('Native ordinal2542 build mismatch')
    candidates=[(n,b) for n,b in modules.items() if n.lower().endswith('\\twinui.dll') and Path(n).resolve()==old.resolve()]
    if not candidates:
        bootstrap.load_library(old);candidates=[(n,b) for n,b in bootstrap.modules().items() if n.lower().endswith('\\twinui.dll') and Path(n).resolve()==old.resolve()]
    if len(candidates)!=1:raise RuntimeError('Exactly one verified old twinui required')
    twinuiPath,twinui=candidates[0]
    image=pefile.PE(str(old));slots=[i for d in image.DIRECTORY_ENTRY_IMPORT if d.dll.lower()==b'user32.dll' for i in d.imports if i.ordinal==2542 and i.address-image.OPTIONAL_HEADER.ImageBase==IAT_RVA]
    if len(slots)!=1:raise RuntimeError('Old PTP import identity mismatch')
    if bootstrap.read(twinui+BRANCH_RVA,6)!=OLD_BRANCH or bootstrap.read(twinui+DISABLED_RVA,7)!=DISABLED_BYTES:raise RuntimeError('Old component policy branch mismatch')
    original=bootstrap.read(twinui+IAT_RVA,8)
    if struct.unpack('<Q',original)[0]!=nativeBase+0x73ca0:raise RuntimeError('PTP import is not expected native2542; refuse overwriting foreign hook')
    stubPe=pefile.PE(str(stub));stubExport=next(e for e in stubPe.DIRECTORY_ENTRY_EXPORT.symbols if e.ordinal==2628)
    if stubExport.forwarder or stubExport.address!=0x1000 or stubPe.get_data(0x1000,22)!=STUB_BYTES:raise RuntimeError('Unsupported-operation stub signature mismatch')
    # USVFS may have loaded this physical DLL under virtual C:\Windows\System32
    # before entry. LoadLibrary with identical basename then reuses it, while
    # general bootstrap expects GetModuleFileNameEx to report the requested path.
    # Resolve existing module strictly by its physical section backing instead.
    existing=[(n,b) for n,b in bootstrap.modules().items() if n.lower().endswith('\\u32w10.dll')]
    if len(existing)>1:raise RuntimeError('Ambiguous U32W10 module identity')
    if existing:
        stubModuleName,stubBase=existing[0];stubIdentity=mapped_file_identity(bootstrap,stubBase,stub)
    else:
        stubBase=bootstrap.load_library(stub);stubModuleName=str(stub);stubIdentity=mapped_file_identity(bootstrap,stubBase,stub)
    if bootstrap.read(stubBase+0x1000,22)!=STUB_BYTES:raise RuntimeError('Loaded unsupported stub bytes mismatch')
    newIat=struct.pack('<Q',stubBase+0x1000)
    branch=b'\xe9'+struct.pack('<i',DISABLED_RVA-(BRANCH_RVA+5))+b'\x90'
    try:
        bootstrap.patch(twinui+IAT_RVA,newIat)
        bootstrap.patch(twinui+BRANCH_RVA,branch,True)
        if bootstrap.read(twinui+IAT_RVA,8)!=newIat or bootstrap.read(twinui+BRANCH_RVA,6)!=branch:raise RuntimeError('Touchpad memory patch verification failed')
    except BaseException:
        bootstrap.patch(twinui+BRANCH_RVA,OLD_BRANCH,True);bootstrap.patch(twinui+IAT_RVA,original);raise
    result={'type':'noLegacyTouchpadPolicy','pointerDevices':inventory,'touchpadType4Present':False,'twinuiPath':twinuiPath,'twinuiSha256':OLD_SHA,'branchRva':hex(BRANCH_RVA),'originalBranch':OLD_BRANCH.hex(),'replacementBranch':branch.hex(),'existingDisabledTarget':hex(DISABLED_RVA),'iatRva':hex(IAT_RVA),'originalIat':hex(struct.unpack('<Q',original)[0]),'replacementIat':hex(stubBase+0x1000),'unsupportedApiResult':'FALSE + ERROR_NOT_SUPPORTED50; never called nativefailfast','stubSha256':STUB_SHA,'stubReportedModuleName':stubModuleName,'stubModuleReused':bool(existing),'stubMappedIdentity':stubIdentity,'registryWrites':False,'processMemoryOnly':True,'featureDisabled':'Legacy shell precision-touchpad gestures; ordinary mouse/tablet untouched by this policy'}
    bootstrap.events.append(result);return result
