from pathlib import Path
root=Path(__file__).resolve().parent.parent
source=(root/'work/decode_all_windowmanagement.py').read_text().split("Path('work/windowwatcher/all-ndr.json')")[0]
source=source.replace("if not name.startswith('___x_Windows_CInternal_CApplicationModel_CWindowManagement_CI') or not name.endswith('ProxyVtbl'):continue","if not 'IApplicationFrame' in name or not name.endswith('ProxyVtbl'):continue")
source=source.replace('range(6,count)','range(3,count)')
namespace={'__file__':__file__};exec(compile(source,'offline-frame-ndr','exec'),namespace)
import json
result=namespace['result']
(root/'outputs/Windows10-Components/Lab/AppFrameManagerCompat/interfaces-ndr.json').write_text(json.dumps(result,indent=2),encoding='utf8')
for tag,rows in result.items():
    print(tag,[(name,record['IID'],record['count']) for name,record in rows.items()])
