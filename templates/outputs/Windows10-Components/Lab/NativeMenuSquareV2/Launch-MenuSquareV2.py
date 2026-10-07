"""Three exact menu-corner callers, in a new owned entry-held Explorer only."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib,importlib.util,json,struct,sys
HOME=Path(__file__).resolve().parent
BASE=HOME.parents[1]
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'))
import pefile

def install_menu_square_hook(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored or bootstrap.attached:
        raise RuntimeError('Menu square V2 needs owned entry-held child with debugger detached')
    manifest=json.loads((HOME/'manifest.json').read_text())
    for row in manifest['Files']:
        if hashlib.sha256(Path(row['Path']).read_bytes()).hexdigest()!=row['SHA256']:
            raise RuntimeError('Menu square V2 file changed: '+row['Path'])
    helper=HOME/'MenuSquareV2.dll'
    native=manifest['NativeCallers']
    for row in native:
        if hashlib.sha256(Path(row['path']).read_bytes()).hexdigest()!=row['sha256']:
            raise RuntimeError('Menu square V2 native image changed: '+row['path'])
    spec=importlib.util.spec_from_file_location('menu_v2_identity',BASE/'Launch-TouchpadCompat.py')
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
        if k.WaitForSingleObject(thread,10000)!=0:raise RuntimeError('Menu square V2 initializer timeout; discard owned child')
        result=W.DWORD()
        if not k.GetExitCodeThread(thread,C.byref(result)):raise C.WinError(C.get_last_error())
        installed=struct.unpack('<I',bootstrap.read(module+exports['MenuSquareInstalled'],4))[0]
        event=dict(type='menuSquareCompat',version=2,helperPath=str(helper),helperSHA256=manifest['HelperSHA256'],helperBase=hex(module),mappedIdentity=identity,result=result.value,installed=installed,callers=[],systemFilesModified=False,xamlPanelsChanged=False)
        bootstrap.events.append(event)
        if result.value or installed!=1:raise RuntimeError('Menu square V2 initializer refused: '+str(event))
        slots=struct.unpack('<3Q',bootstrap.read(module+exports['MenuSquareSlots'],24))
        replacements=struct.unpack('<3Q',bootstrap.read(module+exports['MenuSquareReplacements'],24))
        delays=struct.unpack('<3I',bootstrap.read(module+exports['MenuSquareDelayResolved'],12))
        hrs=struct.unpack('<3I',bootstrap.read(module+exports['MenuSquareDelayHRESULT'],12))
        size=pefile.PE(str(helper)).OPTIONAL_HEADER.SizeOfImage
        all_matched=True
        for index,row in enumerate(native):
            matches=[(p,b) for p,b in bootstrap.modules().items() if Path(p).name.casefold()==row['name'].casefold()]
            if len(matches)!=1:raise RuntimeError('Ambiguous native menu image: '+row['name'])
            _,base=matches[0]
            backing=identity_module.mapped_file_identity(bootstrap,base,Path(row['path']))
            pointer=struct.unpack('<Q',bootstrap.read(base+row['iat'],8))[0]
            matched=slots[index]==base+row['iat'] and pointer==replacements[index] and module<=pointer<module+size
            all_matched &= matched
            event['callers'].append(dict(name=row['name'],path=row['path'],base=hex(base),sha256=row['sha256'],mappedIdentity=backing,iatRva=hex(row['iat']),returnRva=hex(row['caller']),iatTarget=hex(pointer),iatMatched=matched,delayResolved=bool(delays[index]),delayHRESULT=hex(hrs[index])))
        event['iatPointsIntoHelper']=all_matched
        event['scope']='own #32768, attr33 value3, exactly uxtheme/PCS/shell32 caller returns'
        if not all_matched:raise RuntimeError('Menu square V2 readback mismatch: '+str(event))
        return event
    finally:k.CloseHandle(thread)
