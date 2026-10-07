from pathlib import Path
import json,sys
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'))
import pefile
namespace={'__file__':str(root/'work/check_usvfs_imports.py')}
exec(compile((root/'work/check_usvfs_imports.py').read_text().split('rows=[]')[0],'offline-export-resolver','exec'),namespace)
old=root/'outputs/Windows10-Components/Image/4/Windows/SystemApps/Microsoft.Windows.Search_cw5n1h2txyewy'
host=Path('C:/Windows/SystemApps/MicrosoftWindows.Client.CBS_cw5n1h2txyewy')
local={p.name.casefold():p for p in old.glob('*.dll')}
original_pe=namespace['pe']
def mapped_pe(path):
    if path.name.casefold() in local:path=local[path.name.casefold()]
    elif (host/path.name).is_file():path=host/path.name
    return original_pe(path)
namespace['pe']=mapped_pe
rows=[]
for path in [old/'SearchApp.exe',*[p for p in old.glob('*.dll')]]:
    image=pefile.PE(str(path)); row={'file':path.name,'missingRegular':[],'missingDelay':[],'imports':[]}
    for kind,entries in [('Regular',getattr(image,'DIRECTORY_ENTRY_IMPORT',[])),('Delay',getattr(image,'DIRECTORY_ENTRY_DELAY_IMPORT',[]))]:
        for entry in entries:
            dll=entry.dll.decode();target,how=namespace['resolve'](dll,path.name)
            row['imports'].append({'dll':dll,'resolved':target,'kind':kind,'count':len(entry.imports)})
            for item in entry.imports:
                symbol=item.name.decode() if item.name else item.ordinal
                result=namespace['check'](dll,symbol,path.name,'host')
                if result['status']!='ok':row['missing'+kind].append({'dll':dll,'symbol':symbol,**result})
    rows.append(row)
lab=root/'outputs/Windows10-Components/Lab/SearchCompat';lab.mkdir(exist_ok=True)
(lab/'dependencies.json').write_text(json.dumps({'offlineOnly':True,'overlayAllLocalOldDlls':True,'files':rows},indent=2),encoding='utf8')
for row in rows:
    print(row['file'],len(row['missingRegular']),len(row['missingDelay']))
    for missing in row['missingRegular'][:5]:print(missing)
