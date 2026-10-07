"""Host callback reuse in a private old-USER32 lab copy; no system writes."""
from pathlib import Path
import sys,json,struct,hashlib,shutil
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
base=Path('outputs/Windows10-Components');src=base/'Lab/SyscallRemap';dst=base/'Lab/PfnCompat';dst.mkdir(parents=True,exist_ok=True)
for n in ['explorer.exe','twinui.pcshell.dll','UZER32.dll','W1N32U.dll']:
 shutil.copyfile(src/n,dst/n)
if (src/'ru-RU').is_dir():shutil.copytree(src/'ru-RU',dst/'ru-RU',dirs_exist_ok=True)
old=(src/'UZER32.dll').read_bytes();original=(base/'Image/4/Windows/System32/user32.dll').read_bytes();p=pefile.PE(data=old);raw=pefile.PE(data=original)
start=0x19560;resume=0x195d6;fail=0x418a0;capacity=resume-start
assert p.get_data(start,capacity)==raw.get_data(start,capacity),'Initializer already changed; refuse blind patch'
iat=next(x.address-p.OPTIONAL_HEADER.ImageBase for d in p.DIRECTORY_ENTRY_IMPORT for x in d.imports if x.name==b'RtlRetrieveNtUserPfn')
code=bytearray()
def emit(b):code.extend(b)
def relative(op,target):
 here=start+len(code);emit(op+struct.pack('<i',target-here-len(op)-4))
emit(bytes.fromhex('48 83 ec 38 31 c0'))
for slot in [0x40,0x48,0x50]:emit(bytes([0x48,0x89,0x44,0x24,slot]))
emit(bytes.fromhex('4c 8d 44 24 50 48 8d 54 24 40 48 8d 4c 24 48'))
relative(b'\xff\x15',iat)
emit(b'\x85\xc0');relative(b'\x0f\x88',fail)
for slot in [0x40,0x48,0x50]:
 emit(bytes([0x48,0x83,0x7c,0x24,slot,0]));relative(b'\x0f\x84',fail)
relative(b'\xe9',resume)
assert len(code)<=capacity
used=len(code);code.extend(b'\x90'*(capacity-len(code)));data=bytearray(old);off=p.get_offset_from_rva(start);data[off:off+capacity]=code
assert p.OPTIONAL_HEADER.DllCharacteristics&0x80==0,'Source lab DLL still FORCE_INTEGRITY'
assert p.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress==0,'Source lab certificate directory not removed'
patched=pefile.PE(data=data);struct.pack_into('<I',data,patched.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),patched.generate_checksum())
(dst/'UZER32.dll').write_bytes(data)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);lines=[{'rva':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in md.disasm(bytes(code[:used]),start)]
assert sum(i['mnemonic']=='call' for i in lines)==1
report={'sourceSHA256':hashlib.sha256(old).hexdigest(),'patchedSHA256':hashlib.sha256(data).hexdigest(),'rva':hex(start),'resumeRVA':hex(resume),'failureRVA':hex(fail),'RtlRetrieveNtUserPfnIatRVA':hex(iat),'bytesUsed':used,'patchCapacity':capacity,'originalBytes':old[off:off+capacity].hex(),'newBytes':bytes(code).hex(),'instructions':lines,'semantics':'Retrieve the three actual native registered callback arrays; require successful NTSTATUS and non-null pointers; execute original old USER32 globals initialization. No second ntdll registration or forced TRUE.','systemFilesModified':False,'remainingRisk':'CSR/GDI/PEB callback shared state is still old initializer logic; owned child tests only.'}
(dst/'pfn-compat-info.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print('Built',dst,'code bytes',used,'sha256',report['patchedSHA256'])
