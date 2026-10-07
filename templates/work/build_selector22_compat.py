from pathlib import Path
import sys,struct,json,hashlib
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
r=Path('outputs/Windows10-Components/Lab/PfnCompat');f=r/'W1N32U.dll';d=bytearray(f.read_bytes());p=pefile.PE(data=d);h=pefile.PE('C:/Windows/System32/win32u.dll')
a=next(x.address for x in h.DIRECTORY_ENTRY_EXPORT.symbols if x.name==b'NtUserRemoteConnectState');stub=h.get_data(a,32)
assert stub[:4]==bytes.fromhex('4c8bd1b8');number=struct.unpack_from('<I',stub,4)[0]
start=next(x.address for x in p.DIRECTORY_ENTRY_EXPORT.symbols if x.name==b'NtUserCallNoParam');off=p.get_offset_from_rva(start);before=bytes(d[off:off+32]);assert before[0]==0xb8 and before[5:7]==b'\x0f\x0b';marker=before[1:5]
code=bytes.fromhex('83f9227407')+b'\xb8'+marker+b'\x0f\x0b'+bytes.fromhex('4c8bd1b8')+struct.pack('<I',number)+b'\x0f\x05\xc3'
assert len(code)<=32;d[off:off+len(code)]=code
q=pefile.PE(data=d);struct.pack_into('<I',d,q.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),q.generate_checksum());f.write_bytes(d)
info={'operation':'NtUserCallNoParam','selector':'0x22','targetHostName':'NtUserRemoteConnectState','targetHostSyscall':hex(number),'rva':hex(start),'originalBytes':before.hex(),'newBytes':code.hex(),'guardRVA':hex(start+10),'patchSHA256':hashlib.sha256(d).hexdigest(),'proof':'old ClientThreadSetup call1db3c ECX22 and host ClientThreadSetup call529b3 named NtUserRemoteConnectState, identical cmp eax1 result use','unsupportedOthers':'mov EAX marker; UD2','systemFilesModified':False}
(r/'selector22-compat-info.json').write_text(json.dumps(info,indent=2));print(info)
