"""Install resource-only routes in one newly owned, entrypoint-paused Explorer."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib,json,sys,importlib.util
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'))
import pefile
HELPER_SHA256='8fde96078271024a39c263d10ec3f23cc5430ef8647fbe5e5f2769a881bd2952'

def api():
    spec=importlib.util.spec_from_file_location('maximum_icon_maps',BASE/'Lab/IconResourceMaximum/IconMappings.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def get_icon_mappings():
    return api().get_icon_mappings()

def install_icon_resource_hook(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored or bootstrap.attached:
        raise RuntimeError('Icon routing requires newly owned entrypoint-held child without debugger')
    routes=api().get_resource_only_routes()
    if len(routes)!=20:raise RuntimeError('Resource route inventory mismatch')
    helper=BASE/'Lab/IconResourceMaximum/IconRoutes.ChildSafe.dll'
    if hashlib.sha256(helper.read_bytes()).hexdigest()!=HELPER_SHA256:raise RuntimeError('Icon route helper hash changed')
    image=pefile.PE(str(helper));exports={e.name.decode():e.address for e in image.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    module=bootstrap.load_library(helper)
    identity_spec=importlib.util.spec_from_file_location('icon_mapped_identity',BASE/'Launch-TouchpadCompat.py')
    identity_module=importlib.util.module_from_spec(identity_spec);identity_spec.loader.exec_module(identity_module)
    identity=identity_module.mapped_file_identity(bootstrap,module,helper)
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateRemoteThread.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,W.DWORD,C.c_void_p];k.CreateRemoteThread.restype=W.HANDLE
    k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
    k.GetExitCodeThread.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];k.GetExitCodeThread.restype=W.BOOL
    k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
    def invoke(export):
        thread=k.CreateRemoteThread(bootstrap.pi.process,None,0,module+exports[export],None,0,None)
        if not thread:raise C.WinError(C.get_last_error())
        try:
            if k.WaitForSingleObject(thread,20000)!=0:raise RuntimeError('Owned icon initializer timeout; discard owned child')
            result=W.DWORD()
            if not k.GetExitCodeThread(thread,C.byref(result)):raise C.WinError(C.get_last_error())
            return result.value
        finally:k.CloseHandle(thread)
    result=invoke('InitializeIconRoutes')
    patches=invoke('GetIconRoutePatchCount') if not result else 0
    event=dict(type='maximumIconResourceRoutes',helperPath=str(helper),helperBase=hex(module),
               helperSHA256=HELPER_SHA256,manifestSHA256=api().EXPECTED_MANIFEST_SHA256,
               mappedIdentity=identity,result=result,patches=patches,
               routes=20,munMappings=110,codeDLLOverlay=False,systemFilesModified=False,
               coverage='Icon/resource imports and lookups; loader exports stay native; USVFS imports excluded')
    bootstrap.events.append(event)
    if result or not patches:raise RuntimeError('Icon routing refused: '+str(event))
    return event
