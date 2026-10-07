from pathlib import Path
import sys,struct,json,uuid
root=Path(__file__).resolve().parents[4];sys.path.insert(0,str(root/'work/pylib'));import pefile
ids=json.loads((Path(__file__).parent/'id-pointer-tables.json').read_text());out={}
for mode,path in [('old',root/'outputs/Windows10-Components/Image/4/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'),('native',Path('C:/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'))]:
 p=pefile.PE(str(path));base=p.OPTIONAL_HEADER.ImageBase;rows=[]
 for row in ids[mode]:
  desc=int(row['pointerRefs'][0]['pointerRVA'],16);factory=struct.unpack('<Q',p.get_data(desc+0x28,8))[0]-base;block=p.get_data(factory,32);ctx=struct.unpack_from('<Q',block,24)[0]-base;data=p.get_data(ctx,40)
  item={'id':row['id'],'descriptorRVA':hex(desc),'factoryRVA':hex(factory),'factoryQwords':[hex(x) for x in struct.unpack('<4Q',block)],'contextRVA':hex(ctx),'contextRaw':data.hex()}
  if len(data)>=40:item.update(subgroup=str(uuid.UUID(bytes_le=data[:16])),setting=str(uuid.UUID(bytes_le=data[16:32])),flags=struct.unpack_from('<II',data,32))
  rows.append(item);print(item)
 out[mode]=rows
(Path(__file__).parent/'power-exact-id-guid-map.json').write_text(json.dumps(out,indent=2))
