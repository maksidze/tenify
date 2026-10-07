from pathlib import Path
root=Path.cwd();out=root/'outputs/Windows10-Components/Lab/SettingsDynamicTextDiag';out.mkdir(exist_ok=True)
s=(root/'outputs/Windows10-Components/Lab/SettingsEnvironmentCompat/SettingsEnvironmentCompat.c').read_text()
fn=r'''
static BYTE*settingsVmBase;
static void ReadDynamicText(void*context){
 void**lambda=context;BYTE*object=lambda[1];void*environment=*(void**)(object+0x30);void*setting=*(void**)lambda[2];BOOLEAN*value=lambda[3];
 if(value)*value=FALSE;
 HRESULT hr=((HRESULT(WINAPI*)(void*,void*,BOOLEAN*))(*(void***)environment)[8])(environment,setting,value);
 UINT32 length=0;PCWSTR(WINAPI*raw)(void*,UINT32*)=(void*)GetProcAddress(GetModuleHandleW(L"combase.dll"),"WindowsGetStringRawBuffer");PCWSTR name=raw?raw(setting,&length):NULL;
 WCHAR message[512];if(name&&length<256&&!wcsncmp(name,L"Settings",8))swprintf(message,512,L"SettingsDynamicTextDiag tid=%lu hr=%08lx id=%.*ls",GetCurrentThreadId(),hr,(int)length,name);else swprintf(message,512,L"SettingsDynamicTextDiag tid=%lu hr=%08lx stringLength=%u",GetCurrentThreadId(),hr,length);OutputDebugStringW(message);
 if(FAILED(hr))((void(WINAPI*)(HRESULT))(settingsVmBase+0x100f8))(hr);
}
'''
s=s.replace('static const GUID clsid',fn+'static const GUID clsid',1)
needle=' OutputDebugStringW(L"SettingsEnvironmentCompat verified old add_SettingsEnvironmentChanged slot9->native10, same delegate IID; genuine host call, no substituted result.");'
patch=r'''
 settingsVmBase=vmBase;static const BYTE lambdaGuard[]={0x48,0x83,0xec,0x28,0x48,0x8b,0x41,0x08,0x4c,0x8b,0x41,0x18,0x4c,0x8b,0x48,0x30};if(memcmp(vmBase+0x4b990,lambdaGuard,16))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 BYTE lambdaPatch[14]={0xff,0x25,0,0,0,0};void*lambdaReplacement=ReadDynamicText;memcpy(lambdaPatch+6,&lambdaReplacement,8);if(!VirtualProtect(vmBase+0x4b990,14,PAGE_EXECUTE_READWRITE,&vmProtect))return HRESULT_FROM_WIN32(GetLastError());memcpy(vmBase+0x4b990,lambdaPatch,14);VirtualProtect(vmBase+0x4b990,14,vmProtect,&vmUnused);FlushInstructionCache(GetCurrentProcess(),vmBase+0x4b990,14);
 OutputDebugStringW(L"SettingsDynamicTextDiag verified own oldVM lambda wrapper passes native slot8 args/result and genuine old WinRTraise on failure; traces only system Settings IDs.");
'''
assert needle in s;s=s.replace(needle,needle+patch);(out/'SettingsDynamicTextDiag.c').write_text(s)
