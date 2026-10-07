from pathlib import Path
import sys,json,struct,uuid
H=Path(__file__).resolve().parent;R=H.parents[3]
sys.path.insert(0,str(R/'work/pylib'));import pefile
p=pefile.PE('C:/Windows/System32/SystemSettings.DataModel.dll');syms=json.loads((R/'work/compat-research/host-settings-datamodel/all-public-symbols.json').read_text());names={s['rva']:s['name'] for s in syms}
lines=[]
for a in [0xac878]:
 lines.append(hex(a))
 for j in range(21):
  v=struct.unpack('<Q',p.get_data(a+j*8,8))[0]-p.OPTIONAL_HEADER.ImageBase
  lines.append(str(j)+' '+hex(v)+' '+names.get(v,''))
(H/'info-vtables.txt').write_text('\n'.join(lines));print('\n'.join(lines))
nt=pefile.PE(str(H.parent.parent/'Image/4/Windows/System32/SettingsHandlers_nt.dll'))
print('NT GUIDS',[(hex(a),str(uuid.UUID(bytes_le=nt.get_data(a,16)))) for a in [0x2a0218,0x29ff20]])
