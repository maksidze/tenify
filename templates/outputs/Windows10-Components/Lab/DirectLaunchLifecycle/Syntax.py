from pathlib import Path
import ast,json
lab=Path(__file__).resolve().parent
paths=list(lab.glob('*.py'))+[lab.parent/'NoVfsShellCompat/Launch-Explorer10-NoVFS.py']
for path in paths:ast.parse(path.read_text(encoding='utf-8-sig'),filename=str(path))
(lab/'python-syntax.json').write_text(json.dumps({'Passed':True,'Files':[str(x) for x in paths]},indent=2),encoding='utf-8')
