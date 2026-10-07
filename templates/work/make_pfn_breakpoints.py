from pathlib import Path
import hashlib,json,sys
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
root=Path('outputs/Windows10-Components/Lab/PfnCompat').resolve(); dll=root/'UZER32.dll';data=dll.read_bytes();p=pefile.PE(data=data)
pts=[(0x1958a,'RtlRetrieveNtUserPfn return'),(0x195d6,'Callback pointers validated'),(0x186c8,'InitializeNtdllUserPfn return'),(0x18757,'CsrClientConnectToServer return'),(0x18765,'CSR version check'),(0x18e72,'USER32 initialization failure')]
obj=[dict(path=str(dll),sha256=hashlib.sha256(data).hexdigest(),points=[dict(rva=r,label=l,expectedByte=p.get_data(r,1).hex()) for r,l in pts])]
(root/'init-breakpoints.json').write_text(json.dumps(obj,indent=2))
