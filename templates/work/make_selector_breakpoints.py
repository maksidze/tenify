from pathlib import Path
import json,hashlib
r=Path('outputs/Windows10-Components/Lab/PfnCompat').resolve();f=r/'init-breakpoints.json';cfg=json.loads(f.read_text());w=r/'W1N32U.dll';cfg.append({'path':str(w),'sha256':hashlib.sha256(w.read_bytes()).hexdigest(),'points':[{'rva':0x10d0,'label':'Unsupported NtUserCallNoParam selector','expectedByte':'b8'}]});(r/'selector-breakpoints.json').write_text(json.dumps(cfg,indent=2))
