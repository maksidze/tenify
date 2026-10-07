import sys,json
sys.path.insert(0,'work/pylib');import pefile
p=pefile.PE('C:/Windows/System32/windowsudk.shellcommon.dll')
for rva in [0x3d6469+7+0xffb20]:print(hex(rva),p.get_data(rva,128).decode('utf16',errors='replace').split('\0')[0])
for tag in ['host-taskbar']:
 for r in json.load(open('work/compat-research/'+tag+'/all-public-symbols.json')):
  if 'DisplayMonitor' in r['name'] and not any(t in r['name'] for t in ['?$','??$']):print(tag,hex(r['rva']),r['name'])






