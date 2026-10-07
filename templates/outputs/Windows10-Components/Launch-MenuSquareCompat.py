"""Square only native classic #32768 popups in a new owned Explorer child."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib,importlib.util,struct,sys
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'))
import pefile
HELPER_SHA256='980874502f591034477f4eb38d1b9dd50c7c69738bbe3143a7465bd68db05165'
UXTHEME_SHA256='8c5347d464b4b74a17fbc7ab84e2e1f18c1b77fae964caf4f8566df5a7a4a07b'
def install_menu_square_hook(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored or bootstrap.attached:
        raise RuntimeError('Menu square requires a new owned entrypoint-held child without debugger')
    helper=BASE/'Lab/MenuAppearanceCompat/MenuSquare.dll'
    if hashlib.sha256(helper.read_bytes()).hexdigest()!=HELPER_SHA256:raise RuntimeError('Menu square helper changed')
    native=Path('C:/Windows/System32/uxtheme.dll')
    if hashlib.sha256(native.read_bytes()).hexdigest()!=UXTHEME_SHA256:raise RuntimeError('Native uxtheme build mismatch')
    spec=importlib.util.spec_from_file_location('menu_identity',BASE/'Launch-TouchpadCompat.py')
    identity_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(identity_module)
    module=bootstrap.load_library(helper)
    identity=identity_module.mapped_file_identity(bootstrap,module,helper)
    exports={e.name.decode():e.address for e in pefile.PE(str(helper)).DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateRemoteThread.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,W.DWORD,C.c_void_p];k.CreateRemoteThread.restype=W.HANDLE
    k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
    k.GetExitCodeThread.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];k.GetExitCodeThread.restype=W.BOOL
    k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
    thread=k.CreateRemoteThread(bootstrap.pi.process,None,0,module+exports['MenuSquareInitialize'],None,0,None)
    if not thread:raise C.WinError(C.get_last_error())
    try:
        if k.WaitForSingleObject(thread,10000)!=0:raise RuntimeError('Menu initializer timeout; discard owned child')
        result=W.DWORD()
        if not k.GetExitCodeThread(thread,C.byref(result)):raise C.WinError(C.get_last_error())
        installed=struct.unpack('<I',bootstrap.read(module+exports['MenuSquareInstalled'],4))[0]
        delay_resolved=struct.unpack('<I',bootstrap.read(module+exports['MenuSquareDelayResolved'],4))[0]
        delay_hr=struct.unpack('<I',bootstrap.read(module+exports['MenuSquareDelayHRESULT'],4))[0]
        themes=[(n,b) for n,b in bootstrap.modules().items() if n.casefold().endswith('\\uxtheme.dll')]
        if len(themes)!=1:raise RuntimeError('Ambiguous uxtheme module')
        _,theme=themes[0];native_identity=identity_module.mapped_file_identity(bootstrap,theme,native)
        slot=struct.unpack('<Q',bootstrap.read(theme+0xa40e0,8))[0]
        size=pefile.PE(str(helper)).OPTIONAL_HEADER.SizeOfImage
        matched=module<=slot<module+size
        event=dict(type='menuSquareCompat',helperPath=str(helper),helperSHA256=HELPER_SHA256,
                   helperBase=hex(module),mappedIdentity=identity,nativeSHA256=UXTHEME_SHA256,
                   nativeMappedIdentity=native_identity,nativeBase=hex(theme),result=result.value,
                   installed=installed,iatRva='0xa40e0',iatTarget=hex(slot),iatPointsIntoHelper=matched,
                   nativeDelayThunkResolved=bool(delay_resolved),nativeDelayProbeHRESULT=hex(delay_hr),
                   scope='own #32768 classic menus, exact native uxtheme rounded-corner caller only',
                   xamlPanelsChanged=False,systemFilesModified=False)
        bootstrap.events.append(event)
        if result.value or installed!=1 or not matched:raise RuntimeError('Menu square initializer refused: '+str(event))
        return event
    finally:k.CloseHandle(thread)
