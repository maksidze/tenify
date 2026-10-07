"""Single authorized setting 11 refresh, with live shell and registry preconditions."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import json, winreg, hashlib, sys, uuid

ROOT = Path(__file__).resolve().parents[4]
EXPECTED = ROOT / 'outputs/Windows10-Components/Runtime/Explorer10/explorer.exe'
P = C.c_void_p
HR = C.c_long
class GUID(C.Structure):
    _fields_ = [('data', C.c_ubyte * 16)]
def guid(text): return GUID.from_buffer_copy(uuid.UUID(text).bytes_le)
def emit(**v): print(json.dumps(v), flush=True)
def call(p, slot, result, types, *values):
    address = C.cast(p, C.POINTER(C.POINTER(P))).contents[slot]
    return C.WINFUNCTYPE(result, P, *types)(address)(p, *values)
def release(p):
    if p: call(p, 2, W.ULONG, [])

k = C.WinDLL('kernel32', use_last_error=True)
u = C.WinDLL('user32', use_last_error=True)
u.GetShellWindow.restype = W.HWND
u.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]; k.OpenProcess.restype = W.HANDLE
k.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
k.GetProcessTimes.argtypes = [W.HANDLE, C.POINTER(W.FILETIME), C.POINTER(W.FILETIME), C.POINTER(W.FILETIME), C.POINTER(W.FILETIME)]
k.CloseHandle.argtypes = [W.HANDLE]
shell_pid = W.DWORD()
assert u.GetWindowThreadProcessId(u.GetShellWindow(), C.byref(shell_pid)) and shell_pid.value == 10488, 'Expected shell 10488 is not current'
handle = k.OpenProcess(0x1000, False, shell_pid.value)
assert handle
try:
    size = W.DWORD(32768); path = C.create_unicode_buffer(size.value)
    assert k.QueryFullProcessImageNameW(handle, 0, path, C.byref(size))
    assert Path(path.value).resolve() == EXPECTED.resolve(), path.value
    birth, end, kernel, user = W.FILETIME(), W.FILETIME(), W.FILETIME(), W.FILETIME()
    assert k.GetProcessTimes(handle, C.byref(birth), C.byref(end), C.byref(kernel), C.byref(user))
    emit(ShellPid=shell_pid.value, ShellPath=path.value, BirthFileTime=(birth.dwHighDateTime<<32)|birth.dwLowDateTime)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced') as key:
        value, kind = winreg.QueryValueEx(key, 'EnableSnapAssistFlyout')
    emit(RegistryValue=value, RegistryKind=kind)
    assert kind == winreg.REG_DWORD and value == 0, 'Registry precondition failed'
    assert hashlib.sha256(Path('C:/Windows/System32/twinui.dll').read_bytes()).hexdigest() == '10ae13c8560cc89abb33425f9b9e6d49368d43f39e73e3845f3f0e191eb5af2f'
    ole = C.OleDLL('ole32')
    ole.CoInitializeEx.argtypes = [P,W.DWORD]; ole.CoInitializeEx.restype = HR
    ole.CoCreateInstance.argtypes = [C.POINTER(GUID),P,W.DWORD,C.POINTER(GUID),C.POINTER(P)]; ole.CoCreateInstance.restype = HR
    assert ole.CoInitializeEx(None,0) >= 0
    provider = P(); cache = P()
    try:
        shell = guid('c2f03a33-21f5-47fa-b4bb-156362a2f239')
        spiid = guid('6d5140c1-7436-11ce-8034-00aa006009fa')
        sid = guid('53660488-8855-460b-a9ab-5cfc6b5012ca')
        iid = guid('4214f6fa-eb36-4e2f-9ca2-23fdc1832df7')
        hr = ole.CoCreateInstance(C.byref(shell), None, 4, C.byref(spiid), C.byref(provider))
        emit(CoCreateImmersiveShell=f'{hr&0xffffffff:08x}'); assert hr >= 0 and provider
        hr = call(provider,3,HR,[C.POINTER(GUID),C.POINTER(GUID),C.POINTER(P)],C.byref(sid),C.byref(iid),C.byref(cache))
        emit(QueryService=f'{hr&0xffffffff:08x}'); assert hr >= 0 and cache
        def read(stage):
            out = (C.c_uint32*3)(0xa55aa55a,0xeeeeeeee,0x55aa55aa)
            hr = call(cache,4,HR,[W.UINT,P],11,C.byref(out,4))
            canaries = out[0] == 0xa55aa55a and out[2] == 0x55aa55aa
            emit(Stage=stage,GetBOOL=f'{hr&0xffffffff:08x}',Setting=11,Value=out[1],Canaries=canaries)
            assert hr >= 0 and canaries
            return out[1]
        read('before')
        still = W.DWORD()
        assert u.GetWindowThreadProcessId(u.GetShellWindow(), C.byref(still)) and still.value == shell_pid.value
        hr = call(cache,3,HR,[W.UINT],11)
        emit(OnSettingChanged=f'{hr&0xffffffff:08x}',Setting=11); assert hr >= 0
        assert read('after') == 0
    finally:
        release(cache); release(provider); ole.CoUninitialize()
finally:
    k.CloseHandle(handle)
