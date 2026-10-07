"""Apply one XAML hosting compatibility cache bit in a new owned child only."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import struct
import sys

BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'))
import pefile

def install_xaml_quirk_hook(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored:
        raise RuntimeError('XAML quirk compatibility requires newly owned entrypoint-paused child')
    if bootstrap.attached:
        raise RuntimeError('Prepare/detach debugger before running the scoped XAML initializer')
    lab=BASE/'Lab/XamlQuirkCompat'
    metadata=json.loads((lab/'adapter-metadata.json').read_text())
    native=Path(metadata['nativeModule'])
    if hashlib.sha256(native.read_bytes()).hexdigest()!=metadata['sha256']:
        raise RuntimeError('Unsupported native XAML build; adapter not loaded')
    helper=lab/'XamlQuirkCompat.dll'
    image=pefile.PE(str(helper))
    exports={s.name.decode():s.address for s in image.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
    module=bootstrap.load_library(helper)
    kernel=C.WinDLL('kernel32',use_last_error=True)
    def bind(name,result,arguments):
        function=getattr(kernel,name);function.restype=result;function.argtypes=arguments;return function
    thread_create=bind('CreateRemoteThread',C.c_void_p,[C.c_void_p,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)])
    wait=bind('WaitForSingleObject',W.DWORD,[C.c_void_p,W.DWORD])
    exit_code=bind('GetExitCodeThread',W.BOOL,[C.c_void_p,C.POINTER(W.DWORD)])
    close=bind('CloseHandle',W.BOOL,[C.c_void_p])
    thread=thread_create(bootstrap.pi.process,None,0,module+exports['XamlQuirkInitialize'],None,0,None)
    if not thread:raise C.WinError(C.get_last_error())
    try:
        if wait(thread,10000)!=0:
            raise RuntimeError('Owned-child scoped XAML initializer timeout; caller must terminate own child')
        result=W.DWORD()
        if not exit_code(thread,C.byref(result)):raise C.WinError(C.get_last_error())
        data=bootstrap.read(module+exports['XamlQuirkState'],48)
        size,version,hr,suppressions,native_base,cache,before,after=struct.unpack('<IIIIQQ8s8s',data)
        event={'type':'xamlQuirkCompat','helperPath':str(helper),'helperBase':hex(module),
               'nativeSha256':metadata['sha256'],'nativeBase':hex(native_base),
               'cache':hex(cache),'cacheBefore':before.hex(),'cacheAfter':after.hex(),
               'result':hex(result.value),'quirk':hex(0x20106),'mask':4,
               'processLocal':True,'onlyOwnedChild':True,'otherQuirksPreserved':False}
        bootstrap.events.append(event)
        expected=bytearray(before);expected[4]&=~4
        if result.value or size!=48 or version!=1 or hr or suppressions or after!=bytes(expected):
            raise RuntimeError('Scoped XAML quirk compatibility failed or cache changed unexpectedly: '+str(event))
        event['otherQuirksPreserved']=True
        return event
    finally:
        close(thread)
