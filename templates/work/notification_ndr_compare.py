from pathlib import Path
import sys,json,struct
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
for tag,src in [('old','outputs/Windows10-Components/Image/4/Windows/System32/NotificationControllerPS.dll'),('host','C:/Windows/System32/NotificationControllerPS.dll')]:
 p=pefile.PE(src);ib=p.OPTIONAL_HEADER.ImageBase
 sy=json.loads(Path(f'work/compat-research/{tag}-notification-ps/all-public-symbols.json').read_text())
 r=next(x['rva'] for x in sy if x['name']=='_INotificationControllerDataSinkStubVtbl')
 q=lambda r:struct.unpack('<Q',p.get_data(r,8))[0]
 server=q(r+8)-ib;stub=q(server)-ib;fmt=q(server+16)-ib;offset=q(server+24)-ib;types=q(stub+64)-ib
 print(tag, {'stubVtbl':hex(r),'server':hex(server),'stub':hex(stub),'procFmt':hex(fmt),'offsets':hex(offset),'typeFmt':hex(types)})
 for i in range(3,7):
  off=struct.unpack('<H',p.get_data(offset+i*2,2))[0]
  print('method',i,'proc',hex(fmt+off),p.get_data(fmt+off,64).hex())
 Path(f'outputs/Windows10-Components/Lab/NotificationCompat/{tag}-ndr-type.bin').write_bytes(p.get_data(types,12000))
