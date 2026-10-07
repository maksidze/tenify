from pathlib import Path
import sys,uuid,json,subprocess
lab=Path(__file__).resolve().parent;root=lab.parents[3];prior=lab.parent/'IconResourceCompat';session=lab.parent/'SettingsSessionCompat'
source=(prior/'IconProbe.c').read_text();a=source.index(' int ids[]={');b=source.index(';fprintf(f,',a)
source=source[:a]+' int ids[201];for(int i=0;i<201;i++)ids[i]=i'+source[b:]
(lab/'StockProbe.c').write_text(source)
cmd=[str(root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'),'cc','-target','x86_64-windows-gnu','-municode','-Wl,--subsystem,windows',str(lab/'StockProbe.c'),'-o',str(lab/'IconProbe.exe'),'-luser32','-lgdi32','-lshell32']
p=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True);assert p.returncode==0,p.stderr
sys.path.insert(0,str(session));import SessionVFS
SessionVFS.LAB=lab;(lab/'private-usvfs-provenance.json').write_bytes((session/'private-usvfs-provenance.json').read_bytes())
nonce=uuid.uuid4().hex;directory=lab/'sessions'/nonce;directory.mkdir(parents=True)
state=dict(Nonce=nonce,Directory=str(directory),VfsProxy=str(directory/'PrivateUSVFS/usvfs_proxy_x64.exe'));state['Files']=SessionVFS.validate(state,True)
code=(prior/'Probe-OwnIcons.py').read_text()
code=code.replace("sys.argv=[str(controller),'--preset','selftest']","source=source.replace(\"bin=base/'Tools/USVFS/bin'\",\"bin=Path(\"+repr("+repr(str(directory/'PrivateUSVFS'))+")+\")\")\nsys.argv=[str(controller),'--preset','selftest']")
start=code.index("   for name in ['imageres.dll.mun','shell32.dll.mun']:")
end=code.index('  si=SI()',start)
replacement="""   records=json.loads((lab/'manifest.json').read_text())['Records']
   for record in records:
    if record['Mode']!='DataOnlyMUNVFS':continue
    src=Path(record['Private']) if preset=='merged-resource-overlay' else Path(record['Old']);target=Path(record['Host'])
    if not link(str(src),str(target),0):raise C.WinError(C.get_last_error())
    mapping.append({'source':str(src),'destination':str(target),'sha256':hashlib.sha256(src.read_bytes()).hexdigest()})
"""
code=code[:start]+replacement+code[end:]
exec(compile(code,str(lab/'Test-Stock.py'),'exec'),{'__file__':str(lab/'Test-Stock.py'),'__name__':'__main__'})
proof=json.loads((lab/'own-resource-icon-probe.json').read_text())
assert not proof['newBlankRegressions']
for a,b in zip(proof['results']['old-resource-overlay']['icons'],proof['results']['merged-resource-overlay']['icons']):assert a['pixelSHA256']==b['pixelSHA256'],a['id']
print('All201stock queries; merged equalsold; no newblank regressions; private logger namespace')
