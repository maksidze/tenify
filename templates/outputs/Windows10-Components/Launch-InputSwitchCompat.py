"""Install the exact-build InputSwitch ABI adapter in our entry-paused Explorer."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib, importlib.util, json, struct, sys

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent.parent / 'work/pylib'))
import pefile

STAT_NAMES = ('version', 'installed', 'installError', 'wrappedControls',
              'callbacks', 'profileQueries', 'imeQueries', 'rejectedNative',
              'nativeScale', 'nativeRotate', 'oldScale', 'oldRotate',
              'discardedBoolean', 'oldIat', 'newIat')

def decode_stats(data):
    return dict(zip(STAT_NAMES, struct.unpack('<13I4xQQ', data)))

def install_input_switch_compat(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored or bootstrap.attached:
        raise RuntimeError('InputSwitch adapter requires owned entry-paused child, debugger detached')
    lab = BASE / 'Lab/InputSwitchCompat'
    manifest_path = lab / 'guard-manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    if manifest['format'] != 1 or (manifest['oldControlSlots'], manifest['nativeControlSlots']) != (16, 18):
        raise RuntimeError('Unsupported InputSwitch adapter manifest')
    if Path(manifest['explorer']['path']).resolve() != bootstrap.exe.resolve():
        raise RuntimeError('InputSwitch adapter Explorer identity mismatch')
    for entry in (manifest['explorer'], manifest['native']):
        if hashlib.sha256(Path(entry['path']).read_bytes()).hexdigest() != entry['sha256']:
            raise RuntimeError('InputSwitch adapter binary build mismatch: ' + entry['path'])
    for name in ('InputSwitchCompat.cpp', 'Guards.h', 'InputSwitchCompat.dll'):
        if hashlib.sha256((lab / name).read_bytes()).hexdigest() != manifest['artifacts'][name]:
            raise RuntimeError('InputSwitch source/build mismatch: ' + name)
    iat = manifest['coCreateIatRva']
    imports = [row for row in bootstrap.layout['imports']
               if row['iatRva'] == iat and row['name'] == 'CoCreateInstance']
    if len(imports) != 1:
        raise RuntimeError('InputSwitch scoped import is not verified Explorer CoCreateInstance')
    before = bootstrap.read(bootstrap.image_base + iat, 8)
    helper = lab / 'InputSwitchCompat.dll'
    image = pefile.PE(str(helper))
    exports = {s.name.decode(): s.address for s in image.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
    module = bootstrap.load_library(helper)
    spec = importlib.util.spec_from_file_location('InputSwitchMappedIdentity', BASE / 'Launch-TouchpadCompat.py')
    identity = importlib.util.module_from_spec(spec); spec.loader.exec_module(identity)
    physical = identity.mapped_file_identity(bootstrap, module, helper)
    kernel = C.WinDLL('kernel32', use_last_error=True)
    def bind(name, result, args):
        f = getattr(kernel, name); f.restype = result; f.argtypes = args; return f
    create = bind('CreateRemoteThread', C.c_void_p, [C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)])
    wait = bind('WaitForSingleObject', W.DWORD, [C.c_void_p, W.DWORD])
    exit_code = bind('GetExitCodeThread', W.BOOL, [C.c_void_p, C.POINTER(W.DWORD)])
    close = bind('CloseHandle', W.BOOL, [C.c_void_p])
    thread = create(bootstrap.pi.process, None, 0, module + exports['InputSwitchCompatInitialize'], None, 0, None)
    if not thread:
        raise C.WinError(C.get_last_error())
    try:
        if wait(thread, 10000) != 0:
            raise RuntimeError('InputSwitch initialization did not finish; terminate owned child')
        code = W.DWORD()
        if not exit_code(thread, C.byref(code)):
            raise C.WinError(C.get_last_error())
        stats_address = module + exports['InputSwitchCompatStats']
        stats = decode_stats(bootstrap.read(stats_address, 72))
        after = struct.unpack('<Q', bootstrap.read(bootstrap.image_base + iat, 8))[0]
        event = {'type': 'inputSwitchCompat', 'pid': int(bootstrap.pi.pid), 'helperPath': str(helper),
                 'helperBase': hex(module), 'physicalIdentity': physical, 'statsAddress': hex(stats_address),
                 'manifestSha256': hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                 'helperSha256': manifest['artifacts']['InputSwitchCompat.dll'],
                 'nativeSha256': manifest['native']['sha256'], 'iatRva': hex(iat),
                 'scopedReturnRva': hex(manifest['scopedReturnRva']), 'threadExitCode': code.value,
                 'stats': stats, 'processMemoryOnly': True, 'visibleResultVerified': False}
        bootstrap.events.append(event)
        if code.value or stats['version'] != 1 or stats['installed'] != 1 or stats['installError']:
            raise RuntimeError('InputSwitch adapter initialization failed: ' + str(event))
        if stats['oldIat'] != struct.unpack('<Q', before)[0] or after != stats['newIat'] or after == stats['oldIat']:
            raise RuntimeError('InputSwitch adapter import readback mismatch')
        return event
    finally:
        close(thread)
