from pathlib import Path
import sys,json
root=Path(__file__).resolve().parent.parent
source=(root/'work/check_usvfs_imports.py').read_text().split('\nrows=[]')[0]
ns={'__file__':str(root/'work/check_usvfs_imports.py')};exec(source,ns);ns['names']=[]
rows=[]
for name in ['explorerframe.dll','shell32.dll','Windows.UI.FileExplorer.dll','comdlg32.dll']:
 p=ns['old']/name;obj=ns['pe'](p);row={'file':name,'missing':[],'delayMissing':[]}
 for kind,ds in [('normal',getattr(obj,'DIRECTORY_ENTRY_IMPORT',[])),('delay',getattr(obj,'DIRECTORY_ENTRY_DELAY_IMPORT',[]))]:
  for d in ds:
   for x in d.imports:
    s=x.name.decode() if x.name else x.ordinal;a=ns['check'](d.dll.decode(),s,name,'host')
    if a['status']!='ok':row['missing' if kind=='normal' else 'delayMissing'].append({'contract':d.dll.decode(),'symbol':s,**a})
 rows.append(row)
print(json.dumps(rows,indent=2));(root/'work/explorer-old-component-imports.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
