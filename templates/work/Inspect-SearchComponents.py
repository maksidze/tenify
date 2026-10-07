"""Read-only PE/manifest comparison for the next shell component."""
import hashlib,json,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'work/pylib'))
import pefile
BASE=ROOT/'outputs/Windows10-Components'
OLD=BASE/'Image/4/Windows/SystemApps/Microsoft.Windows.Search_cw5n1h2txyewy'
HOST=Path('C:/Windows/SystemApps/MicrosoftWindows.Client.CBS_cw5n1h2txyewy')
result={'systemFilesChanged':False,'processesStarted':False,'packages':{}}
for kind,folder in [('old',OLD),('host',HOST)]:
    tree=ET.parse(folder/'AppxManifest.xml').getroot()
    identity=next(x.attrib for x in tree if x.tag.endswith('Identity'))
    applications=[x.attrib for x in tree.iter() if x.tag.endswith('}Application') and any('Search' in str(v) or 'Cortana' in str(v) for v in x.attrib.values())]
    files=[]
    names=['SearchApp.exe','SearchApi.dll','SearchUx.Model.dll','Search.Core.dll'] if kind=='old' else ['SearchHost.exe','SearchUx.UI.dll','SearchUx.Model.dll','SearchUx.Core.dll']
    for name in names:
        path=folder/name
        pe=pefile.PE(str(path))
        exports=[{'name':e.name.decode(errors='replace') if e.name else None,'ordinal':e.ordinal,'rva':hex(e.address)} for e in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])]
        imports={d.dll.decode():[i.name.decode(errors='replace') if i.name else '#'+str(i.ordinal) for i in d.imports] for d in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])}
        delayed={d.dll.decode():[i.name.decode(errors='replace') if i.name else '#'+str(i.ordinal) for i in d.imports] for d in getattr(pe,'DIRECTORY_ENTRY_DELAY_IMPORT',[])}
        files.append({'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'size':path.stat().st_size,'entryPointRva':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'exports':exports,'imports':imports,'delayImports':delayed})
    result['packages'][kind]={'folder':str(folder),'identity':identity,'applications':applications,'files':files}
out=BASE/'Metadata/search-component-comparison.json'
out.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
for kind,package in result['packages'].items():
    print(kind,package['identity'],package['applications'])
    for f in package['files']:
        print(Path(f['path']).name,f['size'],'exports:',f['exports'][:12])
        print('local imports:',{k:v for k,v in f['imports'].items() if 'search' in k.lower()})
