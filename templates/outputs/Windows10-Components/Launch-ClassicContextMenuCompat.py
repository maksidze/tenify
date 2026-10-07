"""Select the native classic CDefView path in an owned entry-paused Explorer."""
from pathlib import Path
import ctypes as C,hashlib,importlib.util,json,struct,sys
from ctypes import wintypes as W
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'))
import pefile

def install_classic_context_menu(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored or bootstrap.attached:
        raise RuntimeError('Classic menu patch requires owned entry-paused detached Explorer')
    expected=BASE/'Runtime/Explorer10/explorer.exe'
    if bootstrap.exe.resolve()!=expected.resolve():raise RuntimeError('Unexpected Explorer identity')
    lab=BASE/'Lab/ClassicContextMenuCompat';manifest=json.loads((lab/'manifest.json').read_text())
    for entry in manifest['Files']:
        if hashlib.sha256(Path(entry['Path']).read_bytes()).hexdigest()!=entry['SHA256']:raise RuntimeError('Classic context dependency changed: '+entry['Path'])
    native=Path('C:/Windows/System32/shell32.dll')
    mods=bootstrap.modules();shell=next((address for path,address in mods.items() if path.casefold()==str(native).casefold()),None)
    if shell is None:raise RuntimeError('Native shell32 module missing')
    original=bytes.fromhex(manifest['Original']);replacement=bytes.fromhex(manifest['Replacement']);site=shell+manifest['Rva']
    if bootstrap.read(site,len(original))!=original:raise RuntimeError('Classic context native branch differs before initialization')
    helper=lab/'ClassicContextMenu.dll';pe=pefile.PE(str(helper));exports={s.name.decode():s.address for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
    module=bootstrap.load_library(helper)
    spec=importlib.util.spec_from_file_location('ClassicMenuMappedIdentity',BASE/'Launch-TouchpadCompat.py');identity=importlib.util.module_from_spec(spec);spec.loader.exec_module(identity)
    physical=identity.mapped_file_identity(bootstrap,module,helper)
    k=C.WinDLL('kernel32',use_last_error=True)
    def api(name,result,args):f=getattr(k,name);f.restype=result;f.argtypes=args;return f
    create=api('CreateRemoteThread',C.c_void_p,[C.c_void_p,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)])
    wait=api('WaitForSingleObject',W.DWORD,[C.c_void_p,W.DWORD]);getexit=api('GetExitCodeThread',W.BOOL,[C.c_void_p,C.POINTER(W.DWORD)]);close=api('CloseHandle',W.BOOL,[C.c_void_p])
    thread=create(bootstrap.pi.process,None,0,module+exports['ClassicContextInitialize'],None,0,None)
    if not thread:raise C.WinError(C.get_last_error())
    try:
        if wait(thread,10000)!=0:raise RuntimeError('Classic context initialization timed out; discard owned child')
        code=W.DWORD()
        if not getexit(thread,C.byref(code)):raise C.WinError(C.get_last_error())
        installed=struct.unpack('<I',bootstrap.read(module+exports['ClassicContextInstalled'],4))[0]
        if code.value or installed!=1 or bootstrap.read(site,len(replacement))!=replacement:raise RuntimeError('Classic context initialization/readback failed')
        result=dict(Installed=True,ThreadExitCode=code.value,HelperPath=str(helper),PhysicalIdentity=physical,Shell32Base=hex(shell),Rva=hex(manifest['Rva']),PatchBytes=len(replacement),NativeClassicPath=True,ProcessMemoryOnly=True,VisibleUIConfirmed=False,ManifestSHA256=hashlib.sha256((lab/'manifest.json').read_bytes()).hexdigest())
        bootstrap.events.append(dict(type='classicContextMenu',**result));return result
    finally:close(thread)
