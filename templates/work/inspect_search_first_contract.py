from pathlib import Path
import sys,json,struct,uuid
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'))
import pefile
exe=root/'outputs/Windows10-Components/Image/4/Windows/SystemApps/Microsoft.Windows.Search_cw5n1h2txyewy/SearchApp.exe'
pe=pefile.PE(str(exe))
data=pe.get_data(0x2ac040,256)
name=data.decode('utf-16le',errors='replace').split('\0')[0]
guid=uuid.UUID(bytes_le=struct.pack('<IIII',0x7cfb31b4,0x3a0e8cc7,0xaeed2c99,0x07e40cf4))
result={'runtimeClass':name,'manifestDll':'SearchApi.dll','requestedIID':str(guid),'caller':'Cortana::Telemetry::TelemetryUtils::Initialize','callerRVA':'0xb0d98','factoryCallRVA':'0xb0ddf','failedBranchRVA':'0xb0e25','throwReturnRVA':'0xb0e2c','stowedHRESULT':'0x80040154','oldExeFailFastRVA':'0x1a5456','occursBeforeMainApplicationStart':True,'directFactoryRoutingRequired':True}
(root/'outputs/Windows10-Components/Lab/SearchCompat/first-runtime-contract.json').write_text(json.dumps(result,indent=2),encoding='utf8')
print(result)
