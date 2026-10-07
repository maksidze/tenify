from pathlib import Path
import sys,struct,json,hashlib
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
r=Path('outputs/Windows10-Components/Lab/PfnCompat');f=r/'W1N32U.dll';d=bytearray(f.read_bytes());p=pefile.PE(data=d);h=pefile.PE('C:/Windows/System32/win32u.dll');section=next(s for s in p.sections if s.Name.startswith(b'.text'));start=(section.VirtualAddress+section.Misc_VirtualSize+15)&~15;off=p.get_offset_from_rva(start)
targets=[(0x22,'NtUserRemoteConnectState'),(0x13,'NtUserLoadUserApiHook')];nums={}
for sel,name in targets:
 x=next(x for x in h.DIRECTORY_ENTRY_EXPORT.symbols if x.name==name.encode());b=h.get_data(x.address,32);assert b[:4]==bytes.fromhex('4c8bd1b8');nums[sel]=struct.unpack_from('<I',b,4)[0]
# cmp22->target22, cmp13->target13, else marker/trap, target22->common, target13 fallthrough common.
code=bytes.fromhex('83f922740c83f913740eb8')+struct.pack('<I',0xe10b030c)+b'\x0f\x0b'+b'\xb8'+struct.pack('<I',nums[0x22])+b'\xeb\x05'+b'\xb8'+struct.pack('<I',nums[0x13])+bytes.fromhex('4c8bd10f05c3')
assert len(code)==35 and d[off:off+len(code)]==b'\0'*len(code)
# Confirm branch targets from emitted code.
c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);ins=list(c.disasm(code,start));assert [i.op_str for i in ins if i.mnemonic=='je']==[hex(start+17),hex(start+24)]
d[off:off+len(code)]=code;entry=next(x.address for x in p.DIRECTORY_ENTRY_EXPORT.symbols if x.name==b'NtUserCallNoParam');eoff=p.get_offset_from_rva(entry);assert d[eoff:eoff+5]==bytes.fromhex('83f9227407');d[eoff:eoff+5]=b'\xe9'+struct.pack('<i',start-entry-5)
struct.pack_into('<I',d,section.get_field_absolute_offset('Misc_VirtualSize'),start+len(code)-section.VirtualAddress)
q=pefile.PE(data=d);struct.pack_into('<I',d,q.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),q.generate_checksum());f.write_bytes(d)
(r/'selector13-compat-info.json').write_text(json.dumps({'dispatcherRVA':hex(start),'guardRVA':hex(start+15),'targets':{hex(k):{'name':name,'hostSyscall':hex(nums[k])} for k,name in targets},'patchSHA256':hashlib.sha256(d).hexdigest(),'proof':'NoParam13 follows RtlIsThreadWithinLoaderCallout in old GetSystemMetricsForDpi115cd and old DrawCaption7a553; host DrawCaption8c993 same surrounding code directly calls NtUserLoadUserApiHook; runtime return115d9 matches old GetSystemMetricsForDpi.','instructions':[f'{i.address:x}: {i.mnemonic} {i.op_str}' for i in ins],'systemFilesModified':False},indent=2));print('dispatcher',hex(start))
