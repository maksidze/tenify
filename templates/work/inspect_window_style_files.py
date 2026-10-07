from pathlib import Path
import sys,json,hashlib
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'work/pylib'))
import pefile
paths={'oldAero':ROOT/'outputs/Windows10-Components/Image/4/Windows/Resources/Themes/aero/aero.msstyles','hostAero':Path('C:/Windows/Resources/Themes/aero/aero.msstyles')}
result={}
for label,p in paths.items():
 pe=pefile.PE(str(p));resources=[]
 if hasattr(pe,'DIRECTORY_ENTRY_RESOURCE'):
  for typ in pe.DIRECTORY_ENTRY_RESOURCE.entries:
   for name in typ.directory.entries:
    for lang in name.directory.entries:
     d=lang.data.struct;b=pe.get_data(d.OffsetToData,d.Size)
     row={'type':str(typ.name) if typ.name else typ.id,'name':str(name.name) if name.name else name.id,'language':lang.id,'size':d.Size}
     if row['type'] in {'PACKTHEM_VERSION','VMAP','CMAP'}:
      row['prefixHex']=b[:64].hex();row['utf16Prefix']=b[:256].decode('utf-16-le','replace')
     resources.append(row)
 result[label]={'path':str(p),'size':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'resourceCount':len(resources),'resources':resources}
for label,p in [('oldUXTheme',ROOT/'outputs/Windows10-Components/Image/4/Windows/System32/uxtheme.dll'),('hostUXTheme',Path('C:/Windows/System32/uxtheme.dll'))]:
 pe=pefile.PE(str(p));result[label]={'path':str(p),'exports':[{'ordinal':e.ordinal,'name':e.name.decode() if e.name else None} for e in pe.DIRECTORY_ENTRY_EXPORT.symbols],'imports':{d.dll.decode():[i.name.decode() if i.name else '#'+str(i.ordinal) for i in d.imports] for d in pe.DIRECTORY_ENTRY_IMPORT}}
(ROOT/'work/window-style-files.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({k:{'size':v.get('size'),'resourceCount':v.get('resourceCount'),'themePrivateExports':[e for e in v.get('exports',[]) if e['name'] and any(s in e['name'] for s in ['OpenTheme','ThemeFile','ValidateTheme'])]} for k,v in result.items()},ensure_ascii=False))
