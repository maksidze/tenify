from pathlib import Path
import sys,json,struct,hashlib,shutil
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
src=Path('outputs/Windows10-Components/Lab/UniversalModelCompat/twinui.pcshell.dll');out=Path('outputs/Windows10-Components/Lab/WindowStaticsCompat');out.mkdir(exist_ok=True)
data=bytearray(src.read_bytes());p=pefile.PE(data=data);align=lambda n,a:(n+a-1)//a*a
ndr=json.loads(Path('work/windowwatcher/all-ndr.json').read_text());old=next(x for x in ndr['old']['IWindowStatics']['methods'] if x['slot']==15);host=next(x for x in ndr['host']['IWindowStatics']['methods'] if x['slot']==17);assert old['parameters']==host['parameters']
site=0x308a4;resume=0x308ab;before=bytes.fromhex('488b074c8b7078');off=p.get_offset_from_rva(site);assert data[off:off+7]==before
hdr=p.sections[-1].get_file_offset()+40;assert hdr+40<=p.sections[0].PointerToRawData;assert not any(data[hdr:hdr+40])
cave=align(p.sections[-1].VirtualAddress+max(p.sections[-1].Misc_VirtualSize,p.sections[-1].SizeOfRawData),p.OPTIONAL_HEADER.SectionAlignment)
code=bytes.fromhex('488b074c8bb088000000');code+=b'\xe9'+struct.pack('<i',resume-(cave+len(code)+5))
raw=align(len(data),p.OPTIONAL_HEADER.FileAlignment);size=align(len(code),p.OPTIONAL_HEADER.FileAlignment);data.extend(bytes(raw+size-len(data)));data[raw:raw+len(code)]=code
data[hdr:hdr+40]=struct.pack('<8sIIIIIIHHI',b'.wmfix\0\0',len(code),cave,size,raw,0,0,0,0,0x60000020)
struct.pack_into('<H',data,p.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),p.FILE_HEADER.NumberOfSections+1)
struct.pack_into('<I',data,p.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),align(cave+len(code),p.OPTIONAL_HEADER.SectionAlignment))
struct.pack_into('<I',data,p.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfCode'),p.OPTIONAL_HEADER.SizeOfCode+size)
patch=b'\xe9'+struct.pack('<i',cave-(site+5))+b'\x90\x90';data[off:off+7]=patch
p2=pefile.PE(data=data);struct.pack_into('<I',data,p2.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),p2.generate_checksum())
(out/'twinui.pcshell.dll').write_bytes(data)
mui=Path('outputs/Windows10-Components/Image/4/Windows/System32/ru-RU/twinui.pcshell.dll.mui')
if mui.exists():
 (out/'ru-RU').mkdir(exist_ok=True);shutil.copy2(mui,out/'ru-RU'/mui.name)
info={'source':str(src.resolve()),'sourceSHA256':hashlib.sha256(src.read_bytes()).hexdigest(),'patchedSHA256':hashlib.sha256(data).hexdigest(),'interface':'IWindowStatics','IID':ndr['old']['IWindowStatics']['IID'],'oldSlot':15,'hostSlot':17,'oldNDR':old,'hostNDR':host,'patches':[{'rva':hex(site),'before':before.hex(),'after':patch.hex(),'resumeRVA':hex(resume)}],'cave':{'rva':hex(cave),'bytes':code.hex(),'section':'.wmfix'},'proof':'WindowEventDispatcher.WindowAdded +128 WindowStatics cached factory +30; actual caller308ea args DWORD WindowId, enum1, IAsyncOperation<boolean>**. Host slot15 expects out DWORD* at R8 and crashes address1. Host17 exact unique signature. Leaf trampoline preserves registers/flags/stack; host proxy and CFG target remain native.'}
info['actualRPCStackProof']={'hostProxyVtblRVA':'0x8e1a8','hostProxyInfoRVA':'0x38a5e0','NDR64OffsetTableRVA':'0x37f208','hostSlot15ProcedureRVA':'0x381fe0','hostSlot17ProcedureRVA':'0x380fd0','crashR15ProxyInfo':'0x38a5e0','crashRSIProcedure':'0x381fe0'}
(out/'windowstatics-slot-patch.json').write_text(json.dumps(info,indent=2));print('SHA',info['patchedSHA256'],'cave',hex(cave),'patch',patch.hex())
