from pathlib import Path
import sys,struct,uuid,json
root=Path(__file__).resolve().parents[4];sys.path.insert(0,str(root/'work/pylib'));import pefile
p=pefile.PE(str(root/'outputs/Windows10-Components/Image/4/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'));base=p.OPTIONAL_HEADER.ImageBase
rows=[]
for i in range(9):
 a,b=struct.unpack('<QQ',p.get_data(0x1a110+16*i,16));key=p.get_string_u_at_rva(a-base).decode();desc=p.get_data(b-base,64);row={'id':key,'descriptorRVA':hex(b-base),'qwords':[hex(v) for v in struct.unpack('<8Q',desc)]};ptr=struct.unpack_from('<Q',desc,0x28)[0]-base;factory=struct.unpack('<4Q',p.get_data(ptr,32));row['factoryRVA']=hex(ptr);row['factoryQwords']=[hex(x) for x in factory];rows.append(row);print(row)
(Path(__file__).parent/'old-id-descriptors.json').write_text(json.dumps(rows,indent=2))
print('GUIDPAIRDATA',p.get_data(0x1a3c0,0xa0).hex())
