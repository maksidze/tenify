from pathlib import Path
import sys,struct,json,hashlib
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
src=Path('outputs/Windows10-Components/Lab/WindowWatcherCompat/twinui.pcshell.dll')
out=Path('outputs/Windows10-Components/Lab/UniversalModelCompat');out.mkdir(exist_ok=True)
data=bytearray(src.read_bytes());p=pefile.PE(data=data)
rva=0x19d324;off=p.get_offset_from_rva(rva);before=bytes.fromhex('488b8030010000');after=bytes.fromhex('488b8010020000')
assert data[off:off+7]==before
ndr=json.loads(Path('work/windowwatcher/all-ndr.json').read_text())
old=next(x for x in ndr['old']['IUniversalAppModel']['methods'] if x['slot']==38)
host=next(x for x in ndr['host']['IUniversalAppModel']['methods'] if x['slot']==66)
assert old['parameters']==host['parameters']
data[off:off+7]=after
p=pefile.PE(data=data);struct.pack_into('<I',data,p.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),p.generate_checksum())
(out/'twinui.pcshell.dll').write_bytes(data)
info={'source':str(src.resolve()),'sourceSHA256':hashlib.sha256(src.read_bytes()).hexdigest(),'patchedSHA256':hashlib.sha256(data).hexdigest(),'patches':[{'rva':hex(rva),'before':before.hex(),'after':after.hex(),'interface':'IUniversalAppModel','method':'get_UniversalTitleBar','oldSlot':38,'hostSlot':66,'IID':'43c44496-73a7-4b25-b876-1df2708e3e45','resultIID':'402af51f-a72c-45b8-8fe3-cff04ed914f1','oldNDR':old,'hostNDR':host}],'proof':'Same interface IID and unique exact NDR result IID. Old call QI at19d262 proven receiver; NULL result at19d353 follows obsolete slot38 host bool getter. No null guard or fake success.'}
(out/'universal-titlebar-slot-patch.json').write_text(json.dumps(info,indent=2));print(json.dumps(info,indent=2))
