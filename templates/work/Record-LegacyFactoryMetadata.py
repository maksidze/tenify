from pathlib import Path
import hashlib,json,sys
root=Path(__file__).resolve().parent.parent;base=root/'outputs/Windows10-Components';sys.path.insert(0,str(root/'work/pylib'));import pefile
paths={'helperSha256':base/'Lab/LegacyClassFactoryCompat/LegacyClassFactoryCompat.dll','oldTwinuiSha256':base/'Image/4/Windows/System32/twinui.dll','oldPCShellSha256':base/'Lab/XamlComponentCompat/twinui.pcshell.dll','managerAdapterSha256':base/'Lab/AppFrameManagerCompat/AppFrameManagerCompat.dll'}
data={k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in paths.items()};data.update(callRva='0x16767',callBytes=pefile.PE(str(paths['oldPCShellSha256'])).get_data(0x16767,7).hex(),scope='one CLSID + one IID + CLSCTX 0x401; other calls retain AppFrame adapter/native behavior')
(base/'Lab/LegacyClassFactoryCompat/adapter-metadata.json').write_text(json.dumps(data,indent=2),encoding='utf8');print(json.dumps(data))
