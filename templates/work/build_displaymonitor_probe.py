from pathlib import Path
import hashlib,json,os,subprocess,sys,uuid
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'work/pylib'))
import pefile
lab=root/'outputs/Windows10-Components/Lab/DisplayMonitorCompat'
pcs=Path(r'C:\Windows\System32\twinui.pcshell.dll')
pe=pefile.PE(str(pcs))
statics=uuid.UUID(bytes_le=pe.get_data(0x766bf8,16))
collection=uuid.UUID(bytes_le=pe.get_data(0x7625c8,16))
udk=Path(r'C:\Windows\System32\windowsudk.shellcommon.dll')
up=pefile.PE(str(udk))
monitor=uuid.UUID(bytes_le=up.get_data(0x4fedd0,16))
assert str(statics)=='5880f31b-ebad-5f8e-9fca-e7ca5cebc6c3'
def guid(u):
 f=u.fields
 return '{0x%08x,0x%04x,0x%04x,{%s}}'%(f[0],f[1],f[2],','.join('0x%02x'%x for x in u.bytes[8:]))
(lab/'ProbeGuids.h').write_text('/* Read from the exact native PCS/UDK images. */\nstatic const GUID DisplayMonitorStaticsIID='+guid(statics)+';\nstatic const GUID DisplayMonitorCollectionIID='+guid(collection)+';\nstatic const GUID DisplayMonitorIID='+guid(monitor)+';\n',encoding='ascii')
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(root/'work/compat-research/zig-cache'))
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-O1','-municode',str(lab/'DisplayMonitorProbe.c'),'-lole32','-luser32','-o',str(lab/'DisplayMonitorProbe.exe')],env=env,check=True)
manifest={'nativePCS':str(pcs),'nativePCSSha256':hashlib.sha256(pcs.read_bytes()).hexdigest(),'nativeUDK':str(udk),'nativeUDKSha256':hashlib.sha256(udk.read_bytes()).hexdigest(),'staticsIID':str(statics),'collectionIID':str(collection),'monitorIID':str(monitor),'artifacts':{n:hashlib.sha256((lab/n).read_bytes()).hexdigest() for n in ['DisplayMonitorProbe.c','ProbeGuids.h','DisplayMonitorProbe.exe']}}
(lab/'build.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
print(json.dumps(manifest))
