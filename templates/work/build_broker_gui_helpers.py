"""Build GUI-subsystem copies only. Never activate a package or launch helper processes."""
from pathlib import Path
import os,sys,json,hashlib,subprocess
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'work/pylib'))
import pefile
lab=root/'outputs/Windows10-Components/Lab'
entry=lab/'BrokerGuiEntry/BrokerGuiEntry.c'
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
specs=[('StartCompat',lab/'StartCompat/StartCompatHostProbe.c',lab/'StartCompat/StartCompatHostProbe.exe'),('SettingsProbe',lab/'SettingsBrokerCompat/SettingsBrokerProbe.c',lab/'SettingsBrokerCompat/SettingsBrokerProbe.exe'),('SettingsDetached',root/'work/SettingsBrokerDetached.c',lab/'SettingsBrokerCompat/SettingsBrokerDetached.exe')]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
rows=[];env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(root/'work/compat-research/zig-cache'))
for name,src,production in specs:
 before=sha(src);out=production.with_name(production.stem+'.Gui.exe')
 cmd=[str(zig),'cc','-target','x86_64-windows-gnu','-municode','-mwindows','-Wl,--subsystem,windows','-Dwmain=BrokerExistingWmain','-O1','-g',str(src),str(entry),'-o',str(out),'-luser32','-ladvapi32','-lshell32']
 result=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW,timeout=90)
 if result.returncode:raise RuntimeError(result.stderr)
 assert sha(src)==before,'Production source changed during build'
 old=pefile.PE(str(production));new=pefile.PE(str(out));assert new.OPTIONAL_HEADER.Subsystem==2
 rows.append(dict(name=name,source=str(src),sourceSha256=before,production=str(production),productionSha256=sha(production),oldSubsystem=old.OPTIONAL_HEADER.Subsystem,guiCopy=str(out),guiSha256=sha(out),newSubsystem=new.OPTIONAL_HEADER.Subsystem,entrypoint=hex(new.OPTIONAL_HEADER.AddressOfEntryPoint),compileCommand=cmd,compileCreationFlags='CREATE_NO_WINDOW',capturedStderr=result.stderr))
report=dict(entrySource=str(entry),entrySha256=sha(entry),rows=rows,productionFilesReplaced=False,helperProcessesLaunched=False,packageActivationPerformed=False,existingWmainSourcesUnchanged=True)
(lab/'BrokerGuiEntry/build-report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps({'guiCopies':[{r['name']:r['newSubsystem']} for r in rows],'productionFilesReplaced':False,'helperProcessesLaunched':False}))
