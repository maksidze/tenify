from pathlib import Path
p=Path('outputs/Windows10-Components/Lab/SettingsDynamicTextDiag/SettingsDynamicTextDiag.c');s=p.read_text().replace('static BYTE*settingsVmBase;','static BYTE*settingsVmBase;\n__declspec(dllexport) volatile HRESULT SettingsDynamicTextLastResult;\n__declspec(dllexport) volatile LONG SettingsDynamicTextCalls;');s=s.replace(' UINT32 length=0;',' SettingsDynamicTextLastResult=hr;InterlockedIncrement(&SettingsDynamicTextCalls);\n UINT32 length=0;');p.write_text(s)
s=Path('work/Test-SettingsDataModelFactory.c').read_text().replace('argc!=3','argc!=4')
needle='void*environment=NULL,*db=NULL;HRESULT query='
replace='HMODULE helper=LoadLibraryW(argv[3]);DWORD(WINAPI*initHelper)(void*)=helper?(void*)GetProcAddress(helper,"SettingsInitialize"):NULL;DWORD helperHr=initHelper?initHelper(NULL):E_NOINTERFACE;fprintf(log,"HelperInit=%08lx\\n",helperHr);if(helperHr)return 69;void*environment=NULL,*db=NULL;HRESULT query='
assert needle in s;s=s.replace(needle,replace)
needle='query=((HRESULT(WINAPI*)(void*,HSTRING,BOOLEAN*))(*(void***)db)[8])(db,setting,&dynamic);'
replace='BYTE facade[0x38]={0};*(void**)(facade+0x30)=db;void*captures[]={NULL,facade,&setting,&dynamic};((void(WINAPI*)(void*))((BYTE*)GetModuleHandleW(L"SystemSettingsViewModel.Desktop.dll")+0x4b990))(captures);HRESULT*recorded=(void*)GetProcAddress(helper,"SettingsDynamicTextLastResult");query=recorded?*recorded:E_UNEXPECTED;'
assert needle in s;s=s.replace(needle,replace);Path('work/Test-SettingsDynamicTextDiag.c').write_text(s)
