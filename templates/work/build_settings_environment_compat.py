from pathlib import Path
import hashlib,json
root=Path.cwd(); out=root/'outputs/Windows10-Components/Lab/SettingsEnvironmentCompat';out.mkdir(exist_ok=True)
vm=root/'outputs/Windows10-Components/Image/4/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll'
source=(root/'outputs/Windows10-Components/Lab/SettingsMrtCompat/SettingsMrtCompat.c').read_text()
base=source[source.index('static BOOL verifyOldHash'):source.index('static const GUID clsid')]
hashvm=hashlib.sha256(vm.read_bytes()).digest(); hashnative=hashlib.sha256(Path('C:/Windows/System32/SystemSettings.DataModel.dll').read_bytes()).digest()
for name,h in [('verifyVmHash',hashvm),('verifyNativeDataModelHash',hashnative)]:
 f=base.replace('verifyOldHash',name);start=f.index('BYTE expected[]={')+len('BYTE expected[]={');end=f.index('},digest',start);f=f[:start]+','.join('0x%02x'%b for b in h)+f[end:];source=source.replace('static const GUID clsid',f+'static const GUID clsid',1)
insert=r'''
 WCHAR vmPath[]=L"VM_PATH"; WCHAR dmPath[MAX_PATH];UINT length=GetSystemDirectoryW(dmPath,MAX_PATH);if(!length||length>MAX_PATH-40)return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);wcscat(dmPath,L"\\SystemSettings.DataModel.dll");
 if(!verifyVmHash(vmPath)||!verifyNativeDataModelHash(dmPath))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 HMODULE vm=LoadLibraryExW(vmPath,NULL,LOAD_WITH_ALTERED_SEARCH_PATH);if(!vm)return HRESULT_FROM_WIN32(GetLastError());
 BYTE *vmBase=(BYTE*)vm;static const BYTE callBytes[]={0x48,0x8b,0x42,0x48,0x4c,0x8d,0x45,0xd0,0x48,0x8b,0xd7,0x48,0x8b,0xcb};
 if(memcmp(vmBase+0x4b0e4,callBytes,sizeof(callBytes)))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 DWORD vmProtect=0,vmUnused=0;if(!VirtualProtect(vmBase+0x4b0e7,1,PAGE_EXECUTE_READWRITE,&vmProtect))return HRESULT_FROM_WIN32(GetLastError());
 vmBase[0x4b0e7]=0x50;VirtualProtect(vmBase+0x4b0e7,1,vmProtect,&vmUnused);FlushInstructionCache(GetCurrentProcess(),vmBase+0x4b0e7,1);
 OutputDebugStringW(L"SettingsEnvironmentCompat verified old add_SettingsEnvironmentChanged slot9->native10, same delegate IID; genuine host call, no substituted result.");
'''.replace('VM_PATH',str(vm).replace('\\','\\\\'))
source=source.replace(' HANDLE file=CreateFileW(indexFile',insert+' HANDLE file=CreateFileW(indexFile')
(out/'SettingsEnvironmentCompat.c').write_text(source)
(out/'adapter-metadata.json').write_text(json.dumps({'oldVM':str(vm),'oldVMSHA256':hashvm.hex(),'nativeDataModelSHA256':hashnative.hex(),'callsiteRVA':'4b0e4','bytePatchRVA':'4b0e7','oldSlot':9,'hostSlot':10,'delegateIID':'c30dfc1c-e392-4d02-ae09-a8ebf08cbc75','nativeMethod':'add_SettingsEnvironmentChanged','verifiedActualFailureLog':'broker-settings-3749709526df.log','hostAddedSlot9':'IsSettingGlyphDynamic(HSTRING,BOOLEAN*)'},indent=2))
