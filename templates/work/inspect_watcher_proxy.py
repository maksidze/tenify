from pathlib import Path
import struct,json,sys,uuid
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
for tag,path in [('old','work/windowwatcher/old/4/Windows/System32/OneCoreUAPCommonProxyStub.dll'),('host','C:/Windows/System32/OneCoreUAPCommonProxyStub.dll')]:
 p=pefile.PE(path);base=p.OPTIONAL_HEADER.ImageBase;syms=json.loads(Path(f'work/windowwatcher/{tag}-watcher-symbols.json').read_text());q=lambda rv:struct.unpack('<Q',p.get_data(rv,8))[0];
 for typ in ['ProxyVtbl','StubVtbl']:
  sym=next(x for x in syms if x['name']=='___x_Windows_CInternal_CApplicationModel_CWindowManagement_CIWindowWatcher'+typ);rv=sym['rva'];values=struct.unpack('<'+('Q'*10),p.get_data(rv,80));print(tag,typ,hex(rv),[hex(x-base) if base<=x<base+p.OPTIONAL_HEADER.SizeOfImage else hex(x) for x in values])
  if typ=='ProxyVtbl':
   info=values[0]-base;ivs=struct.unpack('<7Q',p.get_data(info,56));print('Info',hex(info),[hex(x-base) if base<=x<base+p.OPTIONAL_HEADER.SizeOfImage else hex(x) for x in ivs]);print('IID',uuid.UUID(bytes_le=p.get_data(values[1]-base,16)));fmt=ivs[1]-base;table=ivs[2]-base
   print('Offsets', [struct.unpack('<H',p.get_data(table+i*2,2))[0] for i in range(3,32)])
   print('Format first',p.get_data(fmt+struct.unpack('<H',p.get_data(table+18*2,2))[0],80).hex())
