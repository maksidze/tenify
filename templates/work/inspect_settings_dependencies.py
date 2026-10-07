from pathlib import Path
import json,sys
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'work/pylib'))
import pefile
namespace={'__file__':str(root/'work/check_usvfs_imports.py')}
source=(root/'work/check_usvfs_imports.py').read_text().split('rows=[]')[0]
exec(compile(source,'offline-export-resolver','exec'),namespace)
old=root/'outputs/Windows10-Components/Image/4/Windows/ImmersiveControlPanel'
host=Path('C:/Windows/ImmersiveControlPanel')
names=['SystemSettings.dll','SystemSettingsViewModel.Desktop.dll','Telemetry.Common.dll']
resolver=namespace['resolve']; original_pe=namespace['pe']
def mapped_pe(path):
    if path.name.casefold() in {x.casefold() for x in names}:
        path=old/path.name if path.parent==namespace['old'] else host/path.name
    return original_pe(path)
namespace['pe']=mapped_pe
namespace['names']=[x.casefold() for x in names]
rows=[]
for name in ['SystemSettings.exe',*names]:
    image=pefile.PE(str(old/name)); row={'file':name,'missingRegular':[],'missingDelay':[],'imports':[]}
    for kind,entries in [('Regular',getattr(image,'DIRECTORY_ENTRY_IMPORT',[])),('Delay',getattr(image,'DIRECTORY_ENTRY_DELAY_IMPORT',[]))]:
        for entry in entries:
            dll=entry.dll.decode(); target,how=resolver(dll,name)
            row['imports'].append({'dll':dll,'resolved':target,'kind':kind,'count':len(entry.imports)})
            for item in entry.imports:
                symbol=item.name.decode() if item.name else item.ordinal
                result=namespace['check'](dll,symbol,name,'overlay')
                if result['status']!='ok':row['missing'+kind].append({'dll':dll,'symbol':symbol,**result})
    row['StartApplication']=[{'name':x.name.decode(),'rva':hex(x.address)} for x in getattr(image,'DIRECTORY_ENTRY_EXPORT',type('Empty',(),{'symbols':[]})()).symbols if x.name==b'StartApplication']
    rows.append(row)
output=root/'outputs/Windows10-Components/Lab/SettingsBrokerCompat/dependencies.json'
output.write_text(json.dumps({'offlineOnly':True,'files':rows},indent=2),encoding='utf-8')
for row in rows:print(row['file'],len(row['missingRegular']),len(row['missingDelay']),row['StartApplication'])
