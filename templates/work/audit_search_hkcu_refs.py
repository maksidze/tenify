from pathlib import Path
import sys,json,winreg,datetime
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'))
import pefile
exe=root/'outputs/Windows10-Components/Image/4/Windows/SystemApps/Microsoft.Windows.Search_cw5n1h2txyewy/SearchApp.exe'
pe=pefile.PE(str(exe));rows=[]
for rva,call in [(0x2ac350,0xb0518),(0x2ac230,0xb055b)]:
    name=pe.get_data(rva,512).decode('utf-16le',errors='replace').split('\0')[0]
    row={'staticKeyReference':'HKCU\\'+name,'stringRva':hex(rva),'RegCreateKeyExCallRva':hex(call),'priorSnapshotAvailable':False,'actualMutationAttributableToProbe':None}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,name,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as key:
            children,values,modified=winreg.QueryInfoKey(key)
            stamp=datetime.datetime(1601,1,1,tzinfo=datetime.timezone.utc)+datetime.timedelta(microseconds=modified//10)
            row.update(existsNow=True,subkeyCount=children,valueCount=values,lastWriteUtc=stamp.isoformat())
    except FileNotFoundError:row['existsNow']=False
    except OSError as error:row['readError']=str(error)
    rows.append(row)
report={'readOnlyAudit':True,'noDeletionOrRollbackWithoutPriorSnapshot':True,'conclusion':'Static RegCreateKeyEx references and current timestamps can be recorded; no prior snapshot exists, so no precise changed-key set can be attributed to owned probes. Registry value data intentionally not collected.','keys':rows}
(root/'outputs/Windows10-Components/Lab/SearchCompat/hkcu-static-current-audit.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps(report,indent=2))
