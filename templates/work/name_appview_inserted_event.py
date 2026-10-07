from pathlib import Path
import json,sys,uuid
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
p=pefile.PE('C:/Windows/System32/OneCoreUAPCommonProxyStub.dll');sy=json.loads(Path('work/windowwatcher/host-appwatcher-symbols.json').read_text());
for x in sy:
 if x['name'].startswith('IID_'):
  g=str(uuid.UUID(bytes_le=p.get_data(x['rva'],16)))
  if g in ['b803b8a3-a02f-5f4d-935c-67d84735e3c8','4f82e701-1352-5464-9e9d-6861d1b021a7','7909ef45-76d7-52db-9918-dc35fa1f8247']:print(g,x['name'])
