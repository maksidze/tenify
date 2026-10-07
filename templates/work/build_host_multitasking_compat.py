"""Patch only a laboratory copy: route Alt+Tab to the retained DComp host.

The host module and Microsoft PDB are required to match the reviewed build.
No USER32, win32u, registration, existing process or system file is changed.
Reference: ExplorerPatcher/TwinUIPatches.cpp, _CreateXamlMTVHostHook.
"""
from pathlib import Path
import hashlib, json, struct, sys, shutil
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'work/pylib'))
import pefile, capstone
SOURCE=Path('C:/Windows/System32/twinui.pcshell.dll')
EXPECTED='b8d9382e2c4b5e7425b4d814eb757bd99ee3c51f21ca7354ac3c7b4c38c4beb9'
OUT=ROOT/'outputs/Windows10-Components/Lab/HostMultitaskingCompat'
data=SOURCE.read_bytes()
sha=lambda x:hashlib.sha256(x).hexdigest()
assert sha(data)==EXPECTED, 'Host DLL differs from the reviewed binary; obtain matching PDB and review again.'
symbols=json.loads((ROOT/'work/compat-research/host-twinui/symbols.json').read_text())
assert symbols['sha256']==EXPECTED and symbols['pdbMatch']
def get_symbol(fragment):
 matches=[x['rva'] for x in symbols['symbols'] if x['name'].startswith('?'+fragment+'@CMultitaskingViewManager@@')]
 assert len(matches)==1,(fragment,matches)
 return matches[0]
xaml=get_symbol('_CreateXamlMTVHost');dcomp=get_symbol('_CreateDCompMTVHost');outer=get_symbol('_CreateMTVHost')
pe=pefile.PE(data=data)
fn=next(x.struct for x in pe.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==outer)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
calls=[x for x in md.disasm(pe.get_data(outer,fn.EndAddress-outer),outer) if x.mnemonic=='call' and x.operands[0].type==capstone.x86.X86_OP_IMM and x.operands[0].imm==xaml]
assert len(calls)==1
site=calls[0].address;assert site==0x18781f
assert data[pe.get_offset_from_rva(site)-5:pe.get_offset_from_rva(site)+12].hex()=='83f8017507e884370d00eb05e801963000', 'Call dispatch changed'
align=lambda n,a:(n+a-1)//a*a
raw_offset=align(len(data),pe.OPTIONAL_HEADER.FileAlignment)
rva=align(max(x.VirtualAddress+max(x.Misc_VirtualSize,x.SizeOfRawData) for x in pe.sections),pe.OPTIONAL_HEADER.SectionAlignment)
thunk=b'\x83\xfa\x01\x75\x05'+b'\xe9'+struct.pack('<i',dcomp-(rva+10))+b'\xe9'+struct.pack('<i',xaml-(rva+15))
section_header=pe.sections[-1].get_file_offset()+40
assert section_header+40<=pe.OPTIONAL_HEADER.SizeOfHeaders
assert not any(data[section_header:section_header+40]),'No spare section header'
patched=bytearray(data);newcall=b'\xe8'+struct.pack('<i',rva-(site+5))
call_offset=pe.get_offset_from_rva(site);patched[call_offset:call_offset+5]=newcall
raw_size=align(len(thunk),pe.OPTIONAL_HEADER.FileAlignment)
header=struct.pack('<8sIIIIIIHHI',b'.w10mtv\0',len(thunk),rva,raw_size,raw_offset,0,0,0,0,0x60000020)
patched[section_header:section_header+40]=header
struct.pack_into('<H',patched,pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),pe.FILE_HEADER.NumberOfSections+1)
struct.pack_into('<I',patched,pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),align(rva+len(thunk),pe.OPTIONAL_HEADER.SectionAlignment))
struct.pack_into('<I',patched,pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfCode'),pe.OPTIONAL_HEADER.SizeOfCode+raw_size)
struct.pack_into('<H',patched,pe.OPTIONAL_HEADER.get_field_absolute_offset('DllCharacteristics'),pe.OPTIONAL_HEADER.DllCharacteristics&~0x80)
cert=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4];struct.pack_into('<II',patched,cert.get_file_offset(),0,0)
patched.extend(bytes(raw_offset-len(patched)));patched.extend(thunk);patched.extend(bytes(raw_size-len(thunk)))
newpe=pefile.PE(data=bytes(patched));struct.pack_into('<I',patched,newpe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),newpe.generate_checksum())
assert bytes(patched[call_offset:call_offset+5])==newcall
decoded=list(md.disasm(thunk,rva));assert decoded[2].operands[0].imm==dcomp and decoded[3].operands[0].imm==xaml
assert sha(SOURCE.read_bytes())==EXPECTED
OUT.mkdir(parents=True,exist_ok=True);dest=OUT/'twinui.pcshell.dll';dest.write_bytes(patched)
mui=[]
for lang in ['ru-RU','en-US']:
    sidecar=SOURCE.parent/lang/(SOURCE.name+'.mui')
    if sidecar.is_file():
        (OUT/lang).mkdir(exist_ok=True);shutil.copy2(sidecar,OUT/lang/sidecar.name)
        mui.append({'language':lang,'source':str(sidecar),'sha256':sha(sidecar.read_bytes())})
version=pe.VS_FIXEDFILEINFO[0]
report={'status':'Built and statically validated; runtime routing not yet tested','source':str(SOURCE),'sourceSha256':EXPECTED,'sourceVersion':'.'.join(str(v) for v in [version.FileVersionMS>>16,version.FileVersionMS&65535,version.FileVersionLS>>16,version.FileVersionLS&65535]),'output':str(dest),'outputSha256':sha(patched),'pdbUrl':symbols['pdbUrl'],'pdbMatch':True,'patch':{'outerRva':hex(outer),'xamlRva':hex(xaml),'dcompRva':hex(dcomp),'callRva':hex(site),'originalCall':data[call_offset:call_offset+5].hex(),'patchedCall':newcall.hex(),'thunkRva':hex(rva),'thunkBytes':thunk.hex(),'behavior':'edx == 1 (Alt+Tab): DComp; otherwise: original XAML'},'signature':'Lab DLL signature invalidated; FORCE_INTEGRITY cleared only on lab copy','systemFileUnchanged':True,'reference':'https://github.com/valinet/ExplorerPatcher/blob/0a88a6e0ef6b1752fea36e581cffff1097e862b0/ExplorerPatcher/TwinUIPatches.cpp#L1054'}
report['mui']=mui
(OUT/'patch-info.json').write_text(json.dumps(report,indent=2),encoding='utf8')
(OUT/'Readme.txt').write_text('Host twinui.pcshell Alt+Tab experiment\n\n'+json.dumps(report,indent=2)+'\n\nUse only as a process-local USVFS mapping in an owned Explorer test child. Keep the host USER32, win32u, provider and appcore; this DLL is already from the host. The new section dispatches type 1 to the existing Windows 10-style DComp host. It leaves Win+Tab and all other XAML invocations unchanged. No claim of successful Alt+Tab startup has been made by this builder.\n',encoding='utf8')
print(json.dumps(report,indent=2))
