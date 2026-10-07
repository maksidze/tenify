import json,sys,struct
sys.path.insert(0,'work/pylib');import pefile
for label,path in [('old','outputs/Windows10-Components/Lab/XamlComponentCompat/twinui.pcshell.dll'),('host','C:/Windows/System32/twinui.pcshell.dll')]:
 s=json.load(open(f'work/compat-research/{label}-twinui/all-public-symbols.json'));ns={}
 for x in s:ns.setdefault(x['rva'],[]).append(x['name'])
 p=pefile.PE(path)
 for r in s:
  if not r['name'].startswith('??_7') or 'UIAllUpViewService' not in r['name'] and 'CAllUpViewService@@' not in r['name']:continue
  a=struct.unpack('<Q',p.get_data(r['rva']+24,8))[0]-p.OPTIONAL_HEADER.ImageBase
  names=[n for n in ns.get(a,[]) if 'ToggleAllUpView@CAllUpViewService' in n]
  if names:print(label,hex(r['rva']),r['name'],'slot3',hex(a),names)
