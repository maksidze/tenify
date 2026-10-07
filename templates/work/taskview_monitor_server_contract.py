import sys,uuid,json
sys.path.insert(0,'work/pylib');import pefile
p=pefile.PE('C:/Windows/System32/Taskbar.dll')
print('FACTORY IID',uuid.UUID(bytes_le=p.get_data(0xe01bd+7+0xf1714,16)))
p=pefile.PE('C:/Windows/System32/windowsudk.shellcommon.dll')
iat={x.address-p.OPTIONAL_HEADER.ImageBase:e.dll.decode()+'!'+(x.name.decode() if x.name else '#'+str(x.ordinal)) for e in p.DIRECTORY_ENTRY_IMPORT for x in e.imports}
for x in [0x25334+7+0x5c9325,0x25416+7+0x47fafb]:print('SERVER IMPORT',hex(x),iat.get(x))
print('SDDL',p.get_data(0x2532d+7+0x49804c,500).decode('utf-16-le',errors='replace').split('\0')[0])
s=json.load(open('work/compat-research/host-udkshellcommon/all-public-symbols.json'))
for r in s:
 if any(x in r['name'] for x in ['SetStaticSafeWorkArea','SetDynamicSafeWorkArea','SetWorkArea','SetDisplayArea','SetIsPrimary','SetRawPixelsPerViewPixel']):print(hex(r['rva']),r['name'])
import struct
ns={r['rva']:r['name'] for r in s}
for i,v in enumerate(struct.unpack('<19Q',p.get_data(0x3d5aa7+7+0xc6c6a,19*8))): print('PRINCIPAL',i,hex(v-p.OPTIONAL_HEADER.ImageBase),ns.get(v-p.OPTIONAL_HEADER.ImageBase,''))

