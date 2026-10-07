"""Install a genuine old ViewEvent delegate proxy in a new owned child only."""
import hashlib
import struct
from pathlib import Path
import sys

BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'))
import pefile

OLD_PROXY_SHA256='c9362fb3ccfb865da7194ac989dfade277e44d7049230b4148581efc687c99ff'
IAT_RVA=0x5448a8
CALL_RVA=0x32a170
CALL_BYTES=bytes.fromhex('48ff1531a72100')

def install_view_delegate_hook(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored:
        raise RuntimeError('View delegate hook requires newly owned entrypoint-paused child')
    lab=BASE/'Lab/ViewDelegateCompat'
    proxy=lab/'ViewEventProxyW10.dll'
    helper=lab/'ViewDelegateProxy.dll'
    if hashlib.sha256(proxy.read_bytes()).hexdigest()!=OLD_PROXY_SHA256:
        raise RuntimeError('Unsupported old ViewEvent proxy build')
    candidates=[]
    for name,base in bootstrap.modules().items():
        if name.endswith('\\twinui.pcshell.dll'):
            try:
                if bootstrap.read(base+CALL_RVA,len(CALL_BYTES))==CALL_BYTES:
                    candidates.append((name,base))
            except OSError:
                continue
    if len(candidates)!=1:
        raise RuntimeError('Expected exactly one old PCS module with verified ViewEvent callsite')
    name,pcs=candidates[0]
    image=pefile.PE(name,fast_load=False)
    slots=[i for d in image.DIRECTORY_ENTRY_IMPORT for i in d.imports
           if i.name==b'RoGetAgileReference' and i.address-image.OPTIONAL_HEADER.ImageBase==IAT_RVA]
    if len(slots)!=1:
        raise RuntimeError('PCS ViewEvent import slot identity mismatch')
    exports=pefile.PE(str(helper)).DIRECTORY_ENTRY_EXPORT.symbols
    rva=next(e.address for e in exports if e.name==b'ViewDelegateRoGetAgileReference')
    old=bootstrap.read(pcs+IAT_RVA,8)
    original=struct.unpack('<Q',old)[0]
    # The current slot must address native combase, not an existing foreign hook.
    combase=[(n,b) for n,b in bootstrap.modules().items() if n.endswith('\\combase.dll')]
    if len(combase)!=1:
        raise RuntimeError('Native combase module identity unavailable')
    native=pefile.PE(combase[0][0])
    expected=combase[0][1]+next(e.address for e in native.DIRECTORY_ENTRY_EXPORT.symbols if e.name==b'RoGetAgileReference')
    if original!=expected:
        raise RuntimeError('PCS RoGetAgileReference is not the native expected export')
    module=bootstrap.load_library(helper)
    replacement=struct.pack('<Q',module+rva)
    try:
        bootstrap.patch(pcs+IAT_RVA,replacement)
        if bootstrap.read(pcs+IAT_RVA,8)!=replacement:
            raise RuntimeError('View delegate IAT verification failed')
    except Exception:
        bootstrap.patch(pcs+IAT_RVA,old)
        raise
    result={'type':'viewDelegateProxy','pcsPath':name,'pcsBase':hex(pcs),
            'iatRva':hex(IAT_RVA),'original':hex(original),'replacement':hex(module+rva),
            'proxySha256':OLD_PROXY_SHA256,'processLocalRegistration':True,
            'registrationDeferredToOriginalCOMApartment':True}
    bootstrap.events.append(result)
    return result
