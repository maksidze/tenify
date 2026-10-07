from pathlib import Path
import struct,json,sys,uuid
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
result={}
for tag,path in [('old','work/windowwatcher/old/4/Windows/System32/OneCoreUAPCommonProxyStub.dll'),('host','C:/Windows/System32/OneCoreUAPCommonProxyStub.dll')]:
 p=pefile.PE(path);base=p.OPTIONAL_HEADER.ImageBase;syms=json.loads(Path(f'work/windowwatcher/{tag}-watcher-symbols.json').read_text());proxy=next(x['rva'] for x in syms if x['name']=='___x_Windows_CInternal_CApplicationModel_CWindowManagement_CIWindowWatcherProxyVtbl');stub=next(x['rva'] for x in syms if x['name']=='___x_Windows_CInternal_CApplicationModel_CWindowManagement_CIWindowWatcherStubVtbl');info,iid=struct.unpack('<QQ',p.get_data(proxy,16));desc,fmt,table=struct.unpack('<QQQ',p.get_data(info-base,24));types=struct.unpack('<Q',p.get_data(desc-base+64,8))[0]-base;count=struct.unpack('<I',p.get_data(stub+16,4))[0];methods=[]
 for slot in range(6,count):
  delta=struct.unpack('<H',p.get_data(table-base+slot*2,2))[0];data=p.get_data(fmt-base+delta,100);assert data[:2]==b'\x33\x6c';opnum,stack,client,server=struct.unpack_from('<4H',data,6);oi2,nargs,extsize=data[14:17];at=16+extsize;params=[]
  for n in range(nargs):
   flags,stackoff,typeval=struct.unpack_from('<HHH',data,at+n*6);row={'attributes':hex(flags),'stackOffset':stackoff}
   if flags&0x40:row['baseType']=hex(typeval&255)
   else:
    row['typeOffset']=hex(typeval);typedata=p.get_data(types+typeval,32);row['typeBytes']=typedata.hex()
    if typedata[:2]==b'\x2f\x5a':row['IID']=str(uuid.UUID(bytes_le=typedata[2:18]))
   params.append(row)
  methods.append({'slot':slot,'vtableOffset':hex(slot*8),'opnum':opnum,'stackBytes':stack,'clientBufferBytes':client,'serverBufferBytes':server,'parameters':params,'procedureBytes':data[:at+nargs*6].hex(),'procedureRVA':hex(fmt-base+delta)})
 result[tag]={'IID':str(uuid.UUID(bytes_le=p.get_data(iid-base,16))),'methodCount':count,'proxyRVA':hex(proxy),'MIDLTypeFormatRVA':hex(types),'methods':methods}
Path('work/windowwatcher/ndr-methods.json').write_text(json.dumps(result,indent=2))
for tag in result:
 print(tag,'IID',result[tag]['IID'])
 for m in result[tag]['methods']:print(m['slot'],m['parameters'])
