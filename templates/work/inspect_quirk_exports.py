from pathlib import Path
import sys,json
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'))
import pefile
rows=[]
for name in ['kernelbase.dll','apphelp.dll','ntdll.dll','kernel32.dll']:
    pe=pefile.PE('C:/Windows/System32/'+name)
    rows.append({'dll':name,'exports':[{'name':s.name.decode(),'rva':hex(s.address),'forwarder':s.forwarder.decode() if s.forwarder else None} for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name and any(x in s.name.lower() for x in [b'quirk',b'compat',b'actctx',b'context'])]})
out=root/'work/quirk-exports.json';out.write_text(json.dumps(rows,indent=2),encoding='utf8')
for row in rows:
    print(row['dll'],[x for x in row['exports'] if 'Quirk' in x['name'] or 'CompatibilityContext' in x['name']])
