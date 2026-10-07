from pathlib import Path
import sys,struct,json,hashlib,shutil
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
base=Path('outputs/Windows10-Components');src=base/'Lab/WindowStaticsCompat/twinui.pcshell.dll';out=base/'Lab/XamlComponentCompat';out.mkdir(exist_ok=True)
proof=json.loads((base/'Lab/ComponentFactoryCompat/direct-factory-probe.json').read_text(encoding='utf8'))
assert proof['getClassObjectHR']==proof['createInstanceIUnknownHR']=='0x0' and proof['factoryNonNull'] and proof['instanceNonNull']
assert proof['descriptor116']['CLSID']=='6e10d302-789d-4237-9037-6a675bdf6511' and proof['descriptor116']['flags']==0
data=bytearray(src.read_bytes());p=pefile.PE(data=data);section=next(s for s in p.sections if s.Name.rstrip(b'\0')==b'.wmfix');cave=section.VirtualAddress+0x20;raw=section.PointerToRawData+0x20;site=0x463c;resume=site+6;target=0x649d58
off=p.get_offset_from_rva(site);before=b'\x89\x15'+struct.pack('<i',target-resume);assert data[off:off+6]==before
code=b'\xc7\x05'+struct.pack('<i',target-(cave+10))+struct.pack('<I',8);code+=b'\xe9'+struct.pack('<i',resume-(cave+15));assert not any(data[raw:raw+len(code)])
data[raw:raw+len(code)]=code;struct.pack_into('<I',data,section.get_file_offset()+8,0x20+len(code));patch=b'\xe9'+struct.pack('<i',cave-(site+5))+b'\x90';data[off:off+6]=patch
p=pefile.PE(data=data);struct.pack_into('<I',data,p.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),p.generate_checksum());(out/'twinui.pcshell.dll').write_bytes(data)
mui=base/'Image/4/Windows/System32/ru-RU/twinui.pcshell.dll.mui'
if mui.exists():(out/'ru-RU').mkdir(exist_ok=True);shutil.copy2(mui,out/'ru-RU'/mui.name)
info={'source':str(src.resolve()),'sourceSHA256':hashlib.sha256(src.read_bytes()).hexdigest(),'patchedSHA256':hashlib.sha256(data).hexdigest(),'componentIndex':116,'CLSID':proof['descriptor116']['CLSID'],'name':'XamlExplorerHost','descriptorFlagsRVA':hex(target),'oldFlags':0,'newFlags':8,'patches':[{'rva':hex(site),'before':before.hex(),'after':patch.hex()}],'cave':{'rva':hex(cave),'bytes':code.hex()},'proof':proof,'semantics':'Use existing old PCShell IImmersiveComponentCreator direct module factory instead of missing global CoCreateInstance registration. Actual old DllGetClassObject(IClassFactory) and CreateInstance(IUnknown) both S_OK in owned hidden child. Preserve required flag1, feature callback, component ordering, original IID and interface construction; no fake success or global registry.'}
(out/'xaml-component-route-patch.json').write_text(json.dumps(info,indent=2,ensure_ascii=False),encoding='utf8');print(info['patchedSHA256'],patch.hex(),code.hex())
