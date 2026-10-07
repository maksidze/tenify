"""Failure-only trace for our private old PCShell copy; no target changes here."""
from pathlib import Path
import sys,json,hashlib
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'work/pylib'))
import pefile
lab=root/'outputs/Windows10-Components/Lab/XamlComponentCompat'
dll=lab/'twinui.pcshell.dll'
pe=pefile.PE(str(dll))
rva=0x285c42
assert pe.get_data(rva,5)==bytes.fromhex('488b4c2438')
config=[{'path':str(dll),'sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),
 'points':[{'rva':rva,'expectedByte':'48','label':'ImmersiveShellBuilder.CreateComponent.Failed',
 'memory':[{'register':'rsi','size':24,'dereference':True},{'register':'rbp','size':16}]}]}]
(lab/'trace-breakpoints.json').write_text(json.dumps(config,indent=2),encoding='utf8')
print('Ready: failure-only component trace with CLSID, flags and requested IID')
