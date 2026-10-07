import json,sys,struct
from pathlib import Path
sys.path.insert(0,'work/pylib');import pefile
out={}
for label,path in [('old','outputs/Windows10-Components/Lab/XamlComponentCompat/twinui.pcshell.dll'),('host','C:/Windows/System32/twinui.pcshell.dll')]:
 s=json.load(open(f'work/compat-research/{label}-twinui/all-public-symbols.json'));names={}
 for r in s:names.setdefault(r['rva'],[]).append(r['name'])
 pe=pefile.PE(path);arr=[]
 for r in s:
  if not r['name'].startswith('??_7'):continue
  if not ('VirtualDesktopNotification' in r['name'] or any(t in r['name'] for t in ('VirtualDesktopDataSource@@','VirtualDesktopItemCollection@@','VirtualDesktopAcessibility@@'))):continue
  if any(x['rva']==hex(r['rva']) for x in arr):continue
  slots=[]
  for k in range(22):
   v=struct.unpack('<Q',pe.get_data(r['rva']+k*8,8))[0]-pe.OPTIONAL_HEADER.ImageBase
   if not any(sec.VirtualAddress<=v<sec.VirtualAddress+sec.Misc_VirtualSize and sec.Characteristics&0x20000000 for sec in pe.sections):break
   ns=names.get(v,[]);slots.append({'slot':k,'rva':hex(v),'names':ns})
  arr.append({'rva':hex(r['rva']),'name':r['name'],'slots':slots})
 out[label]=arr
 print(label,'tables',len(arr))
 for a in arr:
  meaningful=[(x['slot'],x['rva'],[n for n in x['names'] if any(t in n for t in ('VirtualDesktopCreated@','CurrentVirtualDesktopChanged@','ViewVirtualDesktopChanged@','VirtualDesktopDestroyed@','VirtualDesktopDestroyBegin@','VirtualDesktopNameChanged@','VirtualDesktopWallpaperChanged@','VirtualDesktopMoved@'))][:3]) for x in a['slots']]
  meaningful=[x for x in meaningful if x[2]]
  if 'Base@' not in a['name'] and meaningful:print(a['rva'],a['name'],meaningful)
Path('work/vdnotification-vtables.json').write_text(json.dumps(out,indent=2))
