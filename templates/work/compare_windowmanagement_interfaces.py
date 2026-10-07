from pathlib import Path
import json,sys,struct,uuid
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
result={}
for tag,path in [('old','work/windowwatcher/old/4/Windows/System32/OneCoreUAPCommonProxyStub.dll'),('host','C:/Windows/System32/OneCoreUAPCommonProxyStub.dll')]:
 p=pefile.PE(path);base=p.OPTIONAL_HEADER.ImageBase;sy=json.loads(Path(f'work/compat-research/{tag}-windowwatcher-ps/all-public-symbols.json').read_text());byname={x['name']:x['rva'] for x in sy};interfaces={}
 for name,rv in byname.items():
  if not name.startswith('___x_Windows_CInternal_CApplicationModel_CWindowManagement_CI') or not name.endswith('ProxyVtbl'):continue
  stem=name[:-9];srv=byname.get(stem+'StubVtbl')
  if not srv:continue
  info,iid=struct.unpack('<QQ',p.get_data(rv,16));count=struct.unpack('<I',p.get_data(srv+16,4))[0];g=str(uuid.UUID(bytes_le=p.get_data(iid-base,16)));interfaces[stem]={'IID':g,'count':count,'proxy':hex(rv),'stub':hex(srv)}
 result[tag]=interfaces
rows=[]
for name,x in result['old'].items():
 y=result['host'].get(name)
 if not y or x['IID']!=y['IID'] or x['count']!=y['count']:rows.append({'interface':name.split('_CWindowManagement_C')[-1],'old':x,'host':y,'risk':'same IID changed method count' if y and x['IID']==y['IID'] else 'IID/class/interface removed or changed'})
Path('work/windowwatcher/interface-drift-counts.json').write_text(json.dumps(rows,indent=2));print('Interfaces',len(result['old']),len(result['host']),'drift',len(rows));print('\n'.join(f"{x['interface']} {x['old']['count']} -> {x['host']['count'] if x['host'] else None} {x['risk']}" for x in rows))
