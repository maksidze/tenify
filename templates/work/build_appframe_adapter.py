from pathlib import Path
import subprocess,hashlib,json
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/AppFrameManagerCompat'
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-shared','-O1',str(lab/'AppFrameManagerCompat.c'),'-o',str(lab/'AppFrameManagerCompat.dll'),'-lole32','-luuid'],check=True)
meta={'helperSha256':hashlib.sha256((lab/'AppFrameManagerCompat.dll').read_bytes()).hexdigest(),'nativeApplicationFrameSha256':hashlib.sha256(Path('C:/Windows/System32/ApplicationFrame.dll').read_bytes()).hexdigest(),'nativeProxySha256':hashlib.sha256(Path('C:/Windows/System32/OneCoreUAPCommonProxyStub.dll').read_bytes()).hexdigest(),'oldIID':'d6defab3-dbb9-4413-8af9-554586fdff94','nativeIID':'a914f499-4633-4b26-a93e-707eb5bdc0b6','slotMapping':{'3':3,'4':5,'5':6,'6':7,'7':8,'8':9},'serverInfoIID':'5524fe34-8da7-40a8-8165-e8b37a8b4a4b','usesAgileReference':True,'controllingIUnknownPreserved':True,'otherCallsPassthrough':True}
(lab/'adapter-metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf8')
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1',str(lab/'Test-AppFrameManager.c'),'-o',str(lab/'Test-AppFrameManager.exe'),'-lole32','-luuid'],check=True)
print('Built own-process adapter; no registry/package/process activation performed.')
