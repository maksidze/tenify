from pathlib import Path
import hashlib,shutil,json
root=Path.cwd();out=root/'outputs/Windows10-Components/Lab/SettingsDynamicTextCompat';iso=out/'IsolatedOld';iso.mkdir(parents=True,exist_ok=True)
old=root/'outputs/Windows10-Components/Image/4/Windows/System32/SettingsEnvironment.Desktop.dll';copy=iso/old.name;shutil.copy2(old,copy)
s=(root/'outputs/Windows10-Components/Lab/SettingsDynamicTextDiag/SettingsDynamicTextDiag.c').read_text();s=s.replace('SettingsDynamicTextDiag','SettingsDynamicTextCompat')
# Insert genuine hash verification and own old environment initialization before wrapper.
a=s.index('static BOOL verifyVmHash');b=s.index('static BOOL verifyNativeDataModelHash');hashfn=s[a:b].replace('verifyVmHash','verifyOldEnvironmentHash');x=hashfn.index('BYTE expected[]={')+len('BYTE expected[]={');y=hashfn.index('},digest',x);hashfn=hashfn[:x]+','.join('0x%02x'%z for z in hashlib.sha256(old.read_bytes()).digest())+hashfn[y:]
init=r'''
static INIT_ONCE oldEnvironmentOnce=INIT_ONCE_STATIC_INIT;static void*oldEnvironment;static HRESULT oldEnvironmentInit=E_UNEXPECTED;static HMODULE oldEnvironmentModule;
static BOOL CALLBACK initializeOldEnvironment(PINIT_ONCE unused,void*parameter,void**context){
 WCHAR path[]=L"OLD_PATH";if(!verifyOldEnvironmentHash(path)){oldEnvironmentInit=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);return TRUE;}
 oldEnvironmentModule=LoadLibraryExW(path,NULL,LOAD_WITH_ALTERED_SEARCH_PATH);if(!oldEnvironmentModule){oldEnvironmentInit=HRESULT_FROM_WIN32(GetLastError());return TRUE;}
 HRESULT(WINAPI*get)(void**)=(void*)GetProcAddress(oldEnvironmentModule,"GetDesktopSettingsEnvironment");oldEnvironmentInit=get?get(&oldEnvironment):E_NOINTERFACE;return TRUE;
}
'''.replace('OLD_PATH',str(copy).replace('\\','\\\\'))
s=s.replace('static BYTE*settingsVmBase;',hashfn+init+'static BYTE*settingsVmBase;',1)
needle=' SettingsDynamicTextLastResult=hr;InterlockedIncrement(&SettingsDynamicTextCalls);'
new=r'''
 HRESULT nativeResult=hr;
 if(hr==(HRESULT)0x8002802b){
  UINT32 oldLength=0;PCWSTR(WINAPI*readString)(void*,UINT32*)=(void*)GetProcAddress(GetModuleHandleW(L"combase.dll"),"WindowsGetStringRawBuffer");PCWSTR oldName=readString?readString(setting,&oldLength):NULL;
  if(oldName&&oldLength<=256&&!wcsncmp(oldName,L"Settings",8)){
   InitOnceExecuteOnce(&oldEnvironmentOnce,initializeOldEnvironment,NULL,NULL);
   if(SUCCEEDED(oldEnvironmentInit)&&oldEnvironment)hr=((HRESULT(WINAPI*)(void*,LPCWSTR,BOOLEAN*))(*(void***)oldEnvironment)[9])(oldEnvironment,oldName,value);else hr=oldEnvironmentInit;
   WCHAR note[512];swprintf(note,512,L"SettingsDynamicTextCompat genuine fallback native=%08lx old=%08lx value=%u id=%.*ls",nativeResult,hr,value?*value:0,(int)oldLength,oldName);OutputDebugStringW(note);
  }
 }
'''+needle
assert needle in s;s=s.replace(needle,new)
(out/'SettingsDynamicTextCompat.c').write_text(s)
(out/'adapter-metadata.json').write_text(json.dumps({'scope':'Only owned process oldVM dynamic-text lambda native-first fallback','nativeErrorGate':'8002802b TYPE_E_ELEMENTNOTFOUND','oldQuery':'genuine GetDesktopSettingsEnvironment()->UseAlternateText same Settings ID','oldSHA256':hashlib.sha256(old.read_bytes()).hexdigest(),'exactValidatedID':'SettingsPageGroupApps','hostQueryResult':'8002802b FALSE','oldQueryResult':'S_OK TRUE','actualFailedLog':'broker-settings-2f8162f3d34f.log','noFakeResult':True,'existingPublicABISlotFix':'old add9 to host10 only exact validated callsite','systemFilesOrGlobalCOMChanges':False},indent=2))
