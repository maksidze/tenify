from pathlib import Path
import subprocess,hashlib,json,ast
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT/'outputs/Windows10-Components';LAB=BASE/'Lab/Theme10Compat'
cmd=[str(ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'),'cc','-target','x86_64-windows-gnu','-shared','-O2','-o',str(LAB/'Theme10Compat.dll'),str(LAB/'Theme10Compat.c'),'-lbcrypt']
subprocess.run(cmd,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
files=[LAB/'Theme10Compat.c',LAB/'Theme10Compat.dll',BASE/'Launch-Theme10Compat.py',BASE/'Image/4/Windows/Resources/Themes/aero/aero.msstyles',Path('C:/Windows/System32/uxtheme.dll'),BASE/'Runtime/Explorer10/explorer.exe']
data={'scope':'fresh owned Explorer bootstrap only; process-private old theme; native DWM unchanged','nativeOrdinal':127,'nativeRVA':'5f7c0','structSize':88,'files':[{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]}
(LAB/'manifest.json').write_text(json.dumps(data,indent=2),encoding='utf8')
for p in [BASE/'Launch-Theme10Compat.py',BASE/'Launch-Explorer10-VFS.py']:ast.parse(p.read_text(encoding='utf8'))
print('Built',LAB/'Theme10Compat.dll')
