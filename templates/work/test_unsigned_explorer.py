from pathlib import Path
import sys,struct,hashlib,json
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
f=Path('outputs/Explorer10-Xaml/explorer.exe')
data=bytearray(f.read_bytes()); pe=pefile.PE(data=data)
offset=pe.OPTIONAL_HEADER.get_field_absolute_offset('DllCharacteristics')
struct.pack_into('<H',data,offset,pe.OPTIONAL_HEADER.DllCharacteristics & ~0x80)
security=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
struct.pack_into('<II',data,security.get_file_offset(),0,0)
pe=pefile.PE(data=data)
struct.pack_into('<I',data,pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),pe.generate_checksum())
test=Path('work/explorer10-unsigned-test.exe');test.write_bytes(data)
exec(Path('work/debug_old_explorer.py').read_text(encoding='utf-8').split("exe=r'")[0])
exe=str(test.resolve());si=SI();si.cb=C.sizeof(si);pi=PI()
ok=create(exe,C.create_unicode_buffer('"'+exe+'"'),None,None,False,4,None,str(test.parent.resolve()),C.byref(si),C.byref(pi))
print('UNSIGNED_TEST_PREFLIGHT',bool(ok),'error',C.get_last_error())
if ok:term(pi.process,0);close(pi.thread);close(pi.process)
