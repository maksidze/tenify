"""Map the legacy frame-manager ABI to the existing native server in owned child."""
from pathlib import Path
import ctypes as C
import hashlib,json,struct,sys
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'))
import pefile
CALL_RVA=0x1e9368
CALL_BYTES=bytes.fromhex('48ff1529b53500')
IAT_RVA=0x544898
SERVER_CALL_RVA=0x1e9556

def install_appframe_manager_hook(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored:
        raise RuntimeError('Frame manager hook requires a new owned entrypoint-paused child')
    lab=BASE/'Lab/AppFrameManagerCompat'
    metadata=json.loads((lab/'adapter-metadata.json').read_text())
    helper=lab/'AppFrameManagerCompat.dll'
    for path,key in [(helper,'helperSha256'),(Path('C:/Windows/System32/ApplicationFrame.dll'),'nativeApplicationFrameSha256'),(Path('C:/Windows/System32/OneCoreUAPCommonProxyStub.dll'),'nativeProxySha256')]:
        if hashlib.sha256(path.read_bytes()).hexdigest()!=metadata[key]:
            raise RuntimeError('Unsupported frame-manager adapter/native ABI build: '+str(path))
    candidates=[]
    for path,base in bootstrap.modules().items():
        if path.endswith('\\twinui.pcshell.dll'):
            try:
                if bootstrap.read(base+CALL_RVA,len(CALL_BYTES))==CALL_BYTES:
                    candidates.append((path,base))
            except OSError:continue
    if len(candidates)!=1:raise RuntimeError('Expected exactly one verified legacy PCS frame-manager callsite')
    path,pcs=candidates[0]
    image=pefile.PE(path)
    slot=[item for descriptor in image.DIRECTORY_ENTRY_IMPORT for item in descriptor.imports if item.name==b'CoCreateInstance' and item.address-image.OPTIONAL_HEADER.ImageBase==IAT_RVA]
    if len(slot)!=1:raise RuntimeError('PCS frame-manager CoCreate import identity changed')
    if bootstrap.read(pcs+0x5aafc0,16)!=bytes.fromhex('b3fade d6b9db13448af9554586fdff94'.replace(' ','')):
        raise RuntimeError('PCS legacy manager IID changed')
    if bootstrap.read(pcs+0x5aafd0,16)!=bytes.fromhex('9850b0b9303e3f4887f7027ca78da287'):
        raise RuntimeError('PCS frame-manager CLSID changed')
    # Match the full existing server-info helper path; no code patch is needed,
    # because the wrapper exposes its real PID interface with controlling identity.
    original_image=pefile.PE(str(BASE/'Image/4/Windows/System32/twinui.pcshell.dll'))
    server_bytes=original_image.get_data(SERVER_CALL_RVA,5)
    if bootstrap.read(pcs+SERVER_CALL_RVA,5)!=server_bytes:
        raise RuntimeError('PCS frame-manager server-handle caller changed')
    modules=bootstrap.modules();native=[(path,base) for path,base in modules.items() if path.endswith('\\combase.dll')]
    if len(native)!=1:raise RuntimeError('Native combase identity unavailable')
    local=C.WinDLL('kernel32',use_last_error=True)
    local.GetModuleHandleW.argtypes=[C.c_wchar_p];local.GetModuleHandleW.restype=C.c_void_p
    local.GetProcAddress.argtypes=[C.c_void_p,C.c_char_p];local.GetProcAddress.restype=C.c_void_p
    local_combase=local.GetModuleHandleW('combase.dll')
    if not local_combase:
        C.WinDLL('combase.dll');local_combase=local.GetModuleHandleW('combase.dll')
    local_create=local.GetProcAddress(local_combase,b'CoCreateInstance')
    if not local_create:raise RuntimeError('Native CoCreateInstance export unavailable')
    before=bootstrap.read(pcs+IAT_RVA,8);original=struct.unpack('<Q',before)[0]
    expected=native[0][1]+local_create-local_combase
    if original!=expected:raise RuntimeError('Legacy PCS CoCreateInstance already redirected or not native')
    exports=pefile.PE(str(helper)).DIRECTORY_ENTRY_EXPORT.symbols
    rva=next(entry.address for entry in exports if entry.name==b'AppFrameCoCreateInstance')
    module=bootstrap.load_library(helper);replacement=struct.pack('<Q',module+rva)
    try:
        bootstrap.patch(pcs+IAT_RVA,replacement)
        if bootstrap.read(pcs+IAT_RVA,8)!=replacement:raise RuntimeError('Frame-manager IAT verification failed')
    except BaseException:
        bootstrap.patch(pcs+IAT_RVA,before);raise
    result={'type':'appFrameManagerCompat','pcsPath':path,'pcsBase':hex(pcs),'callRva':hex(CALL_RVA),'iatRva':hex(IAT_RVA),'original':hex(original),'replacement':hex(module+rva),'helperSha256':metadata['helperSha256'],'targetClsid':'b9b05098-3e30-483f-87f7-027ca78da287','targetContext':hex(0x404),'oldIID':metadata['oldIID'],'nativeIID':metadata['nativeIID'],'slotMapping':metadata['slotMapping'],'preservesControllingIUnknown':True,'usesNativeServerPID':True,'noGlobalCOMRegistration':True,'otherRequestsPassthrough':True}
    bootstrap.events.append(result)
    return result
