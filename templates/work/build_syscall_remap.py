"""Remap only extracted lab DLLs to this host; guard unavailable entrypoints."""
from pathlib import Path
import sys,json,struct,hashlib,shutil,csv,collections
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
base=Path('outputs/Windows10-Components');raw=base/'Lab/AliasCoreDLLs';lab=base/'Lab/SyscallRemap';lab.mkdir(parents=True,exist_ok=True)
source=base/'Image/4/Windows/System32/win32u.dll';host=Path('C:/Windows/System32/win32u.dll')
original=source.read_bytes();hostBytes=host.read_bytes();oldPE=pefile.PE(data=original);hostPE=pefile.PE(data=hostBytes)
assert oldPE.FILE_HEADER.Machine==hostPE.FILE_HEADER.Machine==0x8664
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
def exports(pe):return {x.name.decode():x for x in pe.DIRECTORY_ENTRY_EXPORT.symbols if x.name}
def syscall(pe,export):
 ins=list(md.disasm(pe.get_data(export.address,32),export.address));number=None;offset=None;found=False
 for i in ins:
  if i.mnemonic=='mov' and i.op_str.startswith('eax, ') and len(i.operands)==2 and i.operands[1].type==capstone.x86.X86_OP_IMM:
   assert i.bytes[0]==0xb8 and i.size==5
   number=i.operands[1].imm;offset=pe.get_offset_from_rva(i.address)+1
  if i.mnemonic=='syscall':found=True
  if i.mnemonic in ['ret','ud2']:break
 return (number,offset) if found and number is not None else (None,None)
old=exports(oldPE);new=exports(hostPE);data=bytearray(original);rows=[];written={}
for name,a in sorted(old.items()):
 b=new.get(name);oldNumber,offset=syscall(oldPE,a);hostNumber,_=syscall(hostPE,b) if b else (None,None)
 row={'name':name,'ordinal':a.ordinal,'rva':hex(a.address),'oldNumber':oldNumber,'hostNumber':hostNumber}
 if oldNumber is None:
  # The sole non-callable export is a data table, not a syscall stub.
  assert name=='gDispatchTableValues',name
  row['action']='data-unchanged'
 elif hostNumber is not None:
  value=struct.pack('<I',hostNumber)
  if offset in written:assert written[offset]==value
  written[offset]=value;data[offset:offset+4]=value
  row.update(action='same' if oldNumber==hostNumber else 'renumbered',fileOffset=offset)
 else:
  # Never execute an old number for an absent or deliberately disabled API.
  # A diagnostic illegal-instruction trap is failure, not fake API support.
  offset=oldPE.get_offset_from_rva(a.address);marker=0xE10B0000|a.ordinal
  value=b'\xb8'+struct.pack('<I',marker)+b'\x0f\x0b'
  if offset in written:assert written[offset]==value
  written[offset]=value;data[offset:offset+len(value)]=value
  row.update(action='guard-missing' if b is None else 'guard-host-non-syscall',fileOffset=offset,marker=hex(marker),trapRVA=hex(a.address+5))
 rows.append(row)
assert len(data)==len(original)
struct.pack_into('<H',data,oldPE.OPTIONAL_HEADER.get_field_absolute_offset('DllCharacteristics'),oldPE.OPTIONAL_HEADER.DllCharacteristics&~0x80)
struct.pack_into('<II',data,oldPE.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset(),0,0)
patched=pefile.PE(data=data);struct.pack_into('<I',data,patched.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),patched.generate_checksum())
patched=pefile.PE(data=data)
for row in rows:
 a=old[row['name']]
 if row['action'] in ['same','renumbered']:assert syscall(patched,a)[0]==row['hostNumber']
 elif row['action'].startswith('guard-'):
  ins=list(md.disasm(patched.get_data(a.address,7),a.address))
  assert [i.mnemonic for i in ins]==['mov','ud2']
for name in ['UZER32.dll','twinui.pcshell.dll','explorer.exe']:
 shutil.copyfile(raw/name,lab/name)
if (raw/'ru-RU').is_dir():shutil.copytree(raw/'ru-RU',lab/'ru-RU',dirs_exist_ok=True)
(lab/'W1N32U.dll').write_bytes(data)
sha=lambda b:hashlib.sha256(b).hexdigest()
report={'hostWin32u':str(host),'hostSHA256':sha(hostBytes),'sourceWin32u':str(source.resolve()),'sourceSHA256':sha(original),'patchedSHA256':sha(data),'summary':dict(collections.Counter(x['action'] for x in rows)),'operations':rows,'exportTableUnchanged':[(x.name,x.ordinal,x.address) for x in oldPE.DIRECTORY_ENTRY_EXPORT.symbols]==[(x.name,x.ordinal,x.address) for x in patched.DIRECTORY_ENTRY_EXPORT.symbols],'systemFilesModified':False,'signature':'Invalid on patched lab copies only','validation':'Every executable export is either a matched host syscall number or explicit UD2 guard; no raw old syscall retained for unavailable API','scope':'Host-specific experiment; parameter structures, dispatch selectors, USER32 initialization and callbacks are NOT adapted'}
(lab/'remap-info.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
fields=['name','ordinal','rva','oldNumber','hostNumber','action','fileOffset','marker','trapRVA']
with (lab/'syscall-remap.csv').open('w',encoding='utf-8-sig',newline='') as f:
 w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
print(json.dumps({k:report[k] for k in ['summary','exportTableUnchanged','systemFilesModified','hostSHA256','patchedSHA256']},indent=2))
