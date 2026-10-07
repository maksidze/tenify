from pathlib import Path
import sys,struct,json,uuid
root=Path(__file__).resolve().parents[4];sys.path.insert(0,str(root/'work/pylib'));import pefile
out={}
for mode,path in [('old',root/'outputs/Windows10-Components/Image/4/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'),('native',Path('C:/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'))]:
 p=pefile.PE(str(path));b=path.read_bytes();base=p.OPTIONAL_HEADER.ImageBase;rows=[]
 ids=['SystemSettings_PowerAndSleep_DisplayOffTimeoutAC','SystemSettings_PowerAndSleep_DisplayOffTimeoutDC','SystemSettings_PowerAndSleep_SleepTimeoutAC','SystemSettings_PowerAndSleep_SleepTimeoutDC'] if mode=='old' else ['SystemSettings_PowerTimeouts_DisplayOff_AC','SystemSettings_PowerTimeouts_DisplayOff_DC','SystemSettings_PowerTimeouts_Sleep_AC','SystemSettings_PowerTimeouts_Sleep_DC']
 for id in ids:
  pos=b.find(id.encode('utf-16le')+b'\0\0');stringRVA=p.get_rva_from_offset(pos);ptr=struct.pack('<Q',base+stringRVA);refs=[];at=0
  while True:
   at=b.find(ptr,at)
   if at<0:break
   rva=p.get_rva_from_offset(at);data=p.get_data(rva,32);nextptr=struct.unpack_from('<Q',data,8)[0]-base;refs.append({'pointerRVA':hex(rva),'nextPointerRVA':hex(nextptr),'raw':data.hex()});at+=8
  rows.append({'id':id,'stringRVA':hex(stringRVA),'pointerRefs':refs})
 out[mode]=rows;print(mode);print(json.dumps(rows,indent=2))
(Path(__file__).parent/'id-pointer-tables.json').write_text(json.dumps(out,indent=2))
