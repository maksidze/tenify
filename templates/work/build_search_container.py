from pathlib import Path
import os,sys,json,struct,hashlib,subprocess
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'work/pylib'))
import pefile
lab=root/'outputs/Windows10-Components/Lab/SearchCompat'
original=root/'outputs/Windows10-Components/Image/4/Windows/SystemApps/Microsoft.Windows.Search_cw5n1h2txyewy/SearchApp.exe'
raw=bytearray(original.read_bytes())
assert hashlib.sha256(raw).hexdigest()=='0da7eea7bb8583a8d994dfbf2dc620feb96b9f6b9f89b60f53a269bfcd2ee1a2'
nt=struct.unpack_from('<I',raw,0x3c)[0]
assert struct.unpack_from('<H',raw,nt+22)[0]==0x22
assert struct.unpack_from('<I',raw,nt+24+16)[0]==0xc8dc0
struct.pack_into('<H',raw,nt+22,0x2022)
struct.pack_into('<I',raw,nt+24+16,0)
container=lab/'SearchUiContainer.dll';container.write_bytes(raw)
pe=pefile.PE(data=bytes(raw));base=pe.OPTIONAL_HEADER.ImageBase
callbacks=[];tls=pe.DIRECTORY_ENTRY_TLS.struct;callback_array=tls.AddressOfCallBacks-base
for position in range(32):
    address=struct.unpack('<Q',pe.get_data(callback_array+position*8,8))[0]
    if not address:break
    callbacks.append({'rva':hex(address-base),'firstByte':pe.get_data(address-base,1).hex()})
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
environment=os.environ.copy();environment['ZIG_GLOBAL_CACHE_DIR']=str(root/'work/compat-research/zig-cache')
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1','-g',str(lab/'SearchContainerProbe.c'),'-o',str(lab/'SearchContainerProbe.exe')],env=environment,check=True)
subprocess.run([sys.executable,str(root/'work/build_search_runtime_controller.py')],check=True)
report={'original':str(original),'container':str(container),'changedBytes':[{'offset':hex(i),'old':a,'new':b} for i,(a,b) in enumerate(zip(original.read_bytes(),raw)) if a!=b],'loaderEntryRVA':0,'originalEntryRVA':'0xc8dc0','mainRVA':'0x7d11c','mainBytes':pe.get_data(0x7d11c,13).hex(),'crtStateRVA':'0x38f524','tlsCallbackArrayRVA':hex(callback_array),'tlsIndexRVA':hex(tls.AddressOfIndex-base),'tlsRawStartRVA':hex(tls.StartAddressOfRawData-base),'tlsRawSize':tls.EndAddressOfRawData-tls.StartAddressOfRawData,'tlsCallbacks':callbacks,'hashes':{name:hashlib.sha256((lab/name).read_bytes()).hexdigest() for name in ['SearchUiContainer.dll','SearchContainerProbe.exe','SearchRuntimeRouter.dll']}}
(lab/'container-build.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps(report,indent=2))
