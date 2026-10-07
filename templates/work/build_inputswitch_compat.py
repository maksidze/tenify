"""Build exact-build, process-local InputSwitch adapter; never change system files."""
from pathlib import Path
import hashlib, json, os, subprocess, sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'work/pylib'))
import pefile, capstone

LAB = ROOT / 'outputs/Windows10-Components/Lab/InputSwitchCompat'
LAB.mkdir(parents=True, exist_ok=True)
EXE = ROOT / 'outputs/Windows10-Components/Runtime/Explorer10/explorer.exe'
NATIVE = Path(os.environ['SystemRoot']) / 'System32/InputSwitch.dll'
EXPECTED_EXE = 'b059f455b37047f4e2b5eae01b21715e4baa304888ac31e44905b41ff6bbcbd0'
EXPECTED_NATIVE = '587ed34d684ef819df0fad8a124e32345a28c4a73808981d4767722a45a5250c'
pe, np = pefile.PE(str(EXE)), pefile.PE(str(NATIVE))
assert hashlib.sha256(EXE.read_bytes()).hexdigest() == EXPECTED_EXE
assert hashlib.sha256(NATIVE.read_bytes()).hexdigest() == EXPECTED_NATIVE
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def guard(label, image, start, minimum):
    items = []
    for ins in md.disasm(image.get_data(start, minimum + 15), start):
        items.append({'rva': ins.address, 'bytes': ins.bytes.hex(), 'asm': ins.mnemonic + ' ' + ins.op_str})
        if ins.address + ins.size >= start + minimum:
            break
    raw = ''.join(x['bytes'] for x in items)
    return {'name': label, 'rva': start, 'bytes': raw, 'instructions': items}

old_guards = [guard(n, pe, a, sz) for n, a, sz in [
    ('RegisterInputSwitch_CoCreate_and_Init', 0x8dff0, 0x62),
    ('RegisterInputSwitch_SetCallback', 0x8e052, 0x2e),
    ('GetCurrentProfile_GetContextFlags', 0x8db65, 0x40),
    ('UpdateCallback', 0xe9b0, 0x2e),
    ('CreateFont_rotation', 0x278e20, 0x12),
    ('FallbackFont_rotation', 0x27996f, 0x21),
]]
native_guards = [guard(n, np, a, sz) for n, a, sz in [
    ('GetCurrentProfile_112byte', 0x1bf20, 0x63),
    ('CopyProfile_new_flag', 0x1c07b, 0x19),
    ('CopyProfile_default_font', 0x1c0f2, 0x1f),
    ('CopyProfile_override_font', 0x1c192, 0x21),
    ('CopyImeModeItem_40byte_zero_tail', 0x19028, 0x2b),
    ('CopyImeModeItem_success_no_tail_ownership', 0x19159, 0x41),
]]
imports = [(imp.address-pe.OPTIONAL_HEADER.ImageBase, ent.dll.decode())
           for ent in pe.DIRECTORY_ENTRY_IMPORT for imp in ent.imports if imp.name == b'CoCreateInstance']
assert len(imports) == 1, imports
iat_rva, import_dll = imports[0]
call = list(md.disasm(pe.get_data(0x8e02e, 7), 0x8e02e))[0]
assert call.size == 7 and 0x8e035 + int.from_bytes(call.bytes[3:], 'little', signed=True) == iat_rva
vtable = [int.from_bytes(np.get_data(0x88cb0+i*8, 8), 'little')-np.OPTIONAL_HEADER.ImageBase for i in range(18)]
manifest = {'format': 1, 'explorer': {'path': str(EXE), 'sha256': EXPECTED_EXE},
            'native': {'path': str(NATIVE), 'sha256': EXPECTED_NATIVE,
                       'pdbGuid': 'ae60cb7f-0181-7dbe-4e43-23add0deb0a2', 'pdbAge': 1},
            'coCreateIatRva': iat_rva, 'importDll': import_dll, 'scopedReturnRva': 0x8e035,
            'oldControlSlots': 16, 'nativeControlSlots': 18, 'callbackSlots': 11,
            'oldProfileSize': 104, 'nativeProfileSize': 112, 'nativeControlVtableRva': 0x88cb0,
            'nativeControlMethodRvas': vtable, 'oldInstructionGuards': old_guards,
            'nativeInstructionGuards': native_guards}
(LAB / 'guard-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')

def arr(b): return '{' + ','.join('0x'+b[i:i+2] for i in range(0,len(b),2)) + '}'
lines = ['// Generated from exact hashed files; instruction-complete guards.', '#pragma once',
         'struct CodeGuard { unsigned long rva; unsigned long length; const unsigned char* bytes; };',
         f'static const unsigned char ExpectedExeHash[32] = {arr(EXPECTED_EXE)};',
         f'static const unsigned char ExpectedNativeHash[32] = {arr(EXPECTED_NATIVE)};',
         f'static const unsigned long CoCreateIatRva = 0x{iat_rva:x};',
         'static const unsigned long ScopedReturnRva = 0x8e035;',
         'static const unsigned long NativeVtableRva = 0x88cb0;',
         'static const unsigned long NativeMethodRvas[18] = {'+', '.join(hex(x) for x in vtable)+'};']
for kind, guards in [('Old', old_guards), ('Native', native_guards)]:
    for i,g in enumerate(guards): lines.append(f'static const unsigned char {kind}Bytes{i}[] = {arr(g["bytes"])};')
    lines.append(f'static const CodeGuard {kind}Guards[] = {{'+','.join('{'+hex(g['rva'])+f', sizeof({kind}Bytes{i}), {kind}Bytes{i}'+'}' for i,g in enumerate(guards))+'};')
(LAB / 'Guards.h').write_text('\n'.join(lines)+'\n', encoding='ascii')
zig = ROOT / 'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(ROOT/'work/compat-research/zig-cache'))
base = [str(zig),'c++','-target','x86_64-windows-gnu','-O2','-fno-exceptions','-fno-rtti',
        '-DUNICODE','-D_UNICODE', str(LAB/'InputSwitchCompat.cpp'), '-lole32','-luuid','-luser32','-lbcrypt']
subprocess.run(base+['-shared','-o',str(LAB/'InputSwitchCompat.dll')],env=env,check=True)
subprocess.run(base+['-DINPUTSWITCH_PROBE','-municode','-o',str(LAB/'InputSwitchProbe.exe')],env=env,check=True)
for file in ['InputSwitchCompat.cpp','Guards.h','InputSwitchCompat.dll','InputSwitchProbe.exe']:
    manifest.setdefault('artifacts',{})[file]=hashlib.sha256((LAB/file).read_bytes()).hexdigest()
(LAB/'guard-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
print(json.dumps({'built':str(LAB),'iatRva':hex(iat_rva),'artifacts':manifest['artifacts']}))
