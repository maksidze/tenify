"""Install the exact native WinX legacy renderer adapter in our paused child.

Import-only API. No arbitrary PID, shell launch, user input or registry writes.
The owner must terminate its child on any bootstrap exception.
"""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib, importlib.util, json, struct, sys

BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'))
import pefile

STAT_NAMES=('version','installed','installError','calls','completed','timeouts',
            'menusBuilt','lastItemCount','selected','invoked','lastError','busy',
            'callerThread','apartment','hotkeyCalls','hotkeyInstalled','slotAddress','original','replacement')

def decode_stats(data):
    if len(data)!=88:raise ValueError('WinX stats layout mismatch')
    return dict(zip(STAT_NAMES,struct.unpack('<16I3Q',data)))

def install_winx_compat(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored or bootstrap.attached:
        raise RuntimeError('WinX adapter requires owned entry-paused child, debugger detached')
    lab=BASE/'Lab/WinXCompat';manifest_path=lab/'manifest.json'
    m=json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    if m.get('format')!=1 or m['vtableRva']!=0x6ea9f8 or len(m['methodRvas'])!=5:
        raise RuntimeError('Unsupported WinX manifest')
    if Path(m['dependencies']['explorer']['path']).resolve()!=bootstrap.exe.resolve():
        raise RuntimeError('WinX old Explorer identity mismatch')
    for row in m['dependencies'].values():
        if hashlib.sha256(Path(row['path']).read_bytes()).hexdigest()!=row['sha256']:
            raise RuntimeError('WinX dependency changed: '+row['path'])
    for relative,sha in m['artifacts'].items():
        path=(lab/relative).resolve()
        if hashlib.sha256(path.read_bytes()).hexdigest()!=sha:
            raise RuntimeError('WinX helper/source changed: '+relative)
    spec=importlib.util.spec_from_file_location('WinXMappedIdentity',BASE/'Launch-TouchpadCompat.py')
    identity=importlib.util.module_from_spec(spec);spec.loader.exec_module(identity)
    pcs_path=Path(m['dependencies']['pcs']['path'])
    found=[b for n,b in bootstrap.modules().items() if n.casefold().endswith('\\twinui.pcshell.dll')]
    if len(found)>1:raise RuntimeError('Ambiguous PCS module')
    pcs=found[0] if found else bootstrap.load_library(pcs_path)
    pcs_identity=identity.mapped_file_identity(bootstrap,pcs,pcs_path)
    before=struct.unpack('<5Q',bootstrap.read(pcs+m['vtableRva'],40))
    expected=tuple(pcs+rva for rva in m['methodRvas'])
    if before!=expected:raise RuntimeError('WinX native interface vtable mismatch; refusing foreign hook')
    for guard in m['byteGuards']:
        expected_bytes=bytes.fromhex(guard['bytes'])
        if bootstrap.read(pcs+guard['rva'],len(expected_bytes))!=expected_bytes:
            raise RuntimeError('WinX native interface instruction/IID guard failed')
    helper_name=m.get('helperFile','WinXCompat.dll')
    if helper_name not in ('WinXCompat.dll','WinXCompat.OwnerWindow.dll','WinXCompat.Immersive.dll'):raise RuntimeError('Unsupported WinX helper artifact')
    helper=lab/helper_name;pe=pefile.PE(str(helper))
    exports={e.name.decode():e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    module=bootstrap.load_library(helper);physical=identity.mapped_file_identity(bootstrap,module,helper)
    k=C.WinDLL('kernel32',use_last_error=True)
    create=k.CreateRemoteThread;create.restype=C.c_void_p
    create.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)]
    wait=k.WaitForSingleObject;wait.restype=W.DWORD;wait.argtypes=[C.c_void_p,W.DWORD]
    get_exit=k.GetExitCodeThread;get_exit.restype=W.BOOL;get_exit.argtypes=[C.c_void_p,C.POINTER(W.DWORD)]
    close=k.CloseHandle;close.restype=W.BOOL;close.argtypes=[C.c_void_p]
    thread=create(bootstrap.pi.process,None,0,module+exports['WinXCompatInitialize'],None,0,None)
    if not thread:raise C.WinError(C.get_last_error())
    try:
        if wait(thread,10000)!=0:raise RuntimeError('WinX initialization timeout; terminate owned child')
        code=W.DWORD()
        if not get_exit(thread,C.byref(code)):raise C.WinError(C.get_last_error())
        stats_address=module+exports['WinXCompatStats'];stats=decode_stats(bootstrap.read(stats_address,88))
        after=struct.unpack('<5Q',bootstrap.read(pcs+m['vtableRva'],40))
        hotkey_address=module+exports['WinXHotkeyPointers'];hot_base,hot_site,hot_bridge=struct.unpack('<3Q',bootstrap.read(hotkey_address,24))
        event={'type':'winXCompat','pid':int(bootstrap.pi.pid),'helperPath':str(helper),
               'helperBase':hex(module),'statsAddress':hex(stats_address),'stats':stats,
               'pcsBase':hex(pcs),'pcsPhysicalIdentity':pcs_identity,'helperPhysicalIdentity':physical,
               'helperSha256':m['artifacts'][helper_name],'manifestSha256':hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
               'threadExitCode':code.value,'vtableRva':hex(m['vtableRva']),'changedSlot':3,
               'genuineProvider':'GetMenuItemsAsync/WindowsUdk.UI.MenuItem','processMemoryOnly':True,'visibleResultVerified':False}
        bootstrap.events.append(event)
        if code.value or stats['version']!=1 or stats['installed']!=1 or stats['installError']:
            raise RuntimeError('WinX initialization failed: '+str(event))
        if after[:3]!=before[:3] or after[4]!=before[4] or after[3]!=stats['replacement'] or stats['original']!=before[3]:
            raise RuntimeError('WinX single-slot readback failed')
        if stats['slotAddress']!=pcs+m['vtableRva']+24 or not module<=after[3]<module+pe.OPTIONAL_HEADER.SizeOfImage:
            raise RuntimeError('WinX replacement pointer outside pinned helper')
        if stats['hotkeyInstalled']!=1 or not hot_base or hot_site!=hot_base+m['hotkey']['callRva'] or not hot_bridge:
            raise RuntimeError('WinX hotkey route was not installed')
        event['hotkey']={'base':hex(hot_base),'callsite':hex(hot_site),'bridge':hex(hot_bridge),'nativePhysicalIdentity':identity.mapped_file_identity(bootstrap,hot_base,Path(m['dependencies']['twinui']['path']))}
        call=bootstrap.read(hot_site,5);bridge=bootstrap.read(hot_bridge,14)
        if call!=b'\xe8'+struct.pack('<i',hot_bridge-hot_site-5) or bridge[:6]!=b'\xff\x25\0\0\0\0':
            raise RuntimeError('WinX hotkey single-call readback failed')
        handler=struct.unpack('<Q',bridge[6:])[0]
        if not module<=handler<module+pe.OPTIONAL_HEADER.SizeOfImage:raise RuntimeError('WinX hotkey handler outside helper')
        expected_hot=bytearray.fromhex(m['hotkey']['guardBytes']);offset=m['hotkey']['callRva']-m['hotkey']['guardRva'];expected_hot[offset:offset+5]=call
        if bootstrap.read(hot_base+m['hotkey']['guardRva'],len(expected_hot))!=bytes(expected_hot):raise RuntimeError('WinX hotkey adjacent instructions changed')
        return event
    finally:
        close(thread)
