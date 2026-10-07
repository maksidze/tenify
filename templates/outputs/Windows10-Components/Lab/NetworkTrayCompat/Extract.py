import subprocess,json,hashlib
from pathlib import Path
lab=Path(__file__).resolve().parent;base=lab.parent.parent
cmd=[str(base/'Tools/7-Zip/7z.exe'),'x','D:/sources/install.wim','4/Windows/System32/pnidui.dll','4/Windows/System32/ru-RU/pnidui.dll.mui','4/Windows/System32/en-US/pnidui.dll.mui','-o'+str(lab/'Extracted'),'-y']
p=subprocess.run(cmd,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,text=True)
(lab/'extraction.log').write_text(p.stdout+p.stderr);assert p.returncode==0,p.stdout+p.stderr
src=lab/'Extracted/4/Windows/System32'
for f in src.rglob('*'):
 if f.is_file():
  dest=lab/f.relative_to(src);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(f.read_bytes())
(lab/'extraction.json').write_text(json.dumps(dict(Image='D:/sources/install.wim',Index=4,Command=cmd,Files=[dict(Path=str(f),SHA256=hashlib.sha256(f.read_bytes()).hexdigest()) for f in src.rglob('*') if f.is_file()]),indent=2))
print(p.stdout[-1000:])
