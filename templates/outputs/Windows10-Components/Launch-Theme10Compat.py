"""Process-private old visual style for a newly created, entrypoint-held Explorer."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib,json,struct,sys
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'))
import pefile

def install_theme10(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored or bootstrap.attached:
        raise RuntimeError('Old visual style requires a new owned entrypoint-held child without attached debugger')
    lab=BASE/'Lab/Theme10Compat'
    metadata=json.loads((lab/'manifest.json').read_text(encoding='utf-8'))
    for item in metadata['files']:
        if hashlib.sha256(Path(item['path']).read_bytes()).hexdigest()!=item['sha256']:
            raise RuntimeError('Visual style dependency hash mismatch: '+item['path'])
    helper=lab/'Theme10Compat.dll'
    pe=pefile.PE(str(helper));exports={s.name.decode():s.address for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
    module=bootstrap.load_library(helper)
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateRemoteThread.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,W.DWORD,C.c_void_p];k.CreateRemoteThread.restype=W.HANDLE
    k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
    k.GetExitCodeThread.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];k.GetExitCodeThread.restype=W.BOOL
    k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
    thread=k.CreateRemoteThread(bootstrap.pi.process,None,0,module+exports['Theme10Initialize'],None,0,None)
    if not thread:raise C.WinError(C.get_last_error())
    try:
        if k.WaitForSingleObject(thread,15000)!=0:raise RuntimeError('Old visual style initialization timeout; discard owned child')
        result=W.DWORD()
        if not k.GetExitCodeThread(thread,C.byref(result)):raise C.WinError(C.get_last_error())
        raw=bootstrap.read(module+exports['Theme10State'],1072)
        size,version,hr,applied,native,theme=struct.unpack('<IIIIQQ',raw[:32])
        before=raw[32:552].decode('utf-16le').split('\0',1)[0];after=raw[552:].decode('utf-16le').split('\0',1)[0]
        event=dict(type='theme10',helperPath=str(helper),result=hex(result.value),size=size,version=version,hr=hex(hr),applied=applied,nativeBase=hex(native),themeFile=hex(theme),before=before,after=after,scope='process-private',globalThemeModified=False)
        bootstrap.events.append(event)
        expected=BASE/'Image/4/Windows/Resources/Themes/aero/aero.msstyles'
        if result.value or size!=1072 or version!=1 or hr or applied!=1 or not theme or after.casefold()!=str(expected).casefold():
            raise RuntimeError('Old visual style initialization refused: '+str(event))
        return event
    finally:k.CloseHandle(thread)
