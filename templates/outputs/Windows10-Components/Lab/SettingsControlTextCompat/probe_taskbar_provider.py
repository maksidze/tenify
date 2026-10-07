from pathlib import Path
import subprocess,json,sys,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent.parent
sys.path.insert(0,str(R/'work/pylib'));import pefile,capstone
exe=H/'TaskbarProviderProbe.exe';csc=Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe')
c=subprocess.run([str(csc),'/nologo','/target:winexe','/platform:x64','/out:'+str(exe),str(H/'TaskbarProviderProbe.cs')],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=30);(H/'provider-build.log').write_bytes(c.stdout+c.stderr);c.check_returncode()
report=[]
for mode,path in [('native-oldpri',Path('C:/Windows/System32/SettingsHandlers_nt.dll')),('old-oldpri',B/'Image/4/Windows/System32/SettingsHandlers_nt.dll')]:
 pe=pefile.PE(str(path));rva=next(e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name==b'GetSetting');cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
 (H/(mode+'-nt-export.txt')).write_text('\n'.join(f'{i.address:x} {i.mnemonic} {i.op_str}' for i in cs.disasm(pe.get_data(rva,240),rva)))
 with subprocess.Popen([str(exe),str(H/(mode+'-nt-provider.log')),str(path),hex(rva),str(B/'Image/4/Windows/SystemResources/Windows.UI.SettingsAppThreshold/Windows.UI.SettingsAppThreshold.pri')],creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as child:
  try:o,e=child.communicate(timeout=20);timeout=False
  except subprocess.TimeoutExpired:child.kill();o,e=child.communicate(timeout=5);timeout=True
  report.append(dict(mode=mode,path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),exportRva=hex(rva),pid=child.pid,exit=child.returncode,timeout=timeout))
(H/'taskbar-provider-oldpri-proof.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
