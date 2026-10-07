from pathlib import Path
import hashlib,json
r=Path('outputs/Windows10-Components/Lab/PfnCompat');result={n:hashlib.sha256((r/n).read_bytes()).hexdigest() for n in ['UZER32.dll','W1N32U.dll','explorer.exe','twinui.pcshell.dll']};(r/'final-lab-hashes.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
