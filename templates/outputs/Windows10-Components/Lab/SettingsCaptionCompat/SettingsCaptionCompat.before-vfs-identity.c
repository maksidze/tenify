#define UNICODE
#define _UNICODE
#include <windows.h>
#include <objbase.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
typedef void *HS;
typedef HRESULT (WINAPI *QueryNative)(void*,HS,BOOLEAN*);
typedef HRESULT (WINAPI *QueryOld)(void*,LPCWSTR,BOOLEAN*);
typedef HRESULT (WINAPI *QI)(void*,REFIID,void**);
typedef ULONG (WINAPI *Release)(void*);
static const GUID privateIID={0x0adb9837,0x6628,0x48d2,{0xad,0x8a,0x3c,0x13,0x8c,0xdc,0x9b,0x62}};
static const BYTE lambdaExpected[64]={@GENERATED_GUARD_51@};
static HMODULE selfModule,oldModule,nativeDM;static void *oldEnvironment;
static INIT_ONCE once=INIT_ONCE_STATIC_INIT;static HRESULT initialization=E_PENDING;
static BYTE *vmBase,*hook;static BYTE installed[16];
static PCWSTR(WINAPI*stringRaw)(HS,UINT32*);
__declspec(dllexport) volatile LONG SettingsCaptionOldCalls,SettingsCaptionNativeCalls;
__declspec(dllexport) volatile HRESULT SettingsCaptionLastResult;
__declspec(dllexport) volatile LONG SettingsCaptionInstalled;
static BOOL hashMatches(PCWSTR path,const char *hex){
 BYTE digest[32],buffer[65536];BCRYPT_ALG_HANDLE alg=NULL;BCRYPT_HASH_HANDLE hash=NULL;BYTE*object=NULL;DWORD size=0,used=0,read=0;BOOL ok=FALSE;
 HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);if(file==INVALID_HANDLE_VALUE)return FALSE;
 if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto done;
 if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(BYTE*)&size,4,&used,0)<0)goto done;
 object=HeapAlloc(GetProcessHeap(),0,size);if(!object)goto done;
 if(BCryptCreateHash(alg,&hash,object,size,NULL,0,0)<0)goto done;
 for(;;){if(!ReadFile(file,buffer,sizeof(buffer),&read,NULL))goto done;if(!read)break;if(BCryptHashData(hash,buffer,read,0)<0)goto done;}
 if(BCryptFinishHash(hash,digest,32,0)<0)goto done;ok=TRUE;
 for(int i=0;i<32;i++){char x[3]={hex[2*i],hex[2*i+1],0};if(digest[i]!=(BYTE)strtoul(x,NULL,16)){ok=FALSE;break;}}
 done:if(hash)BCryptDestroyHash(hash);if(alg)BCryptCloseAlgorithmProvider(alg,0);if(object)HeapFree(GetProcessHeap(),0,object);CloseHandle(file);return ok;
}
static BOOL sibling(PCWSTR suffix,PWSTR out){DWORD n=GetModuleFileNameW(selfModule,out,MAX_PATH);if(!n||n>=MAX_PATH)return FALSE;WCHAR*p=wcsrchr(out,L'\\');if(!p)return FALSE;*p=0;p=wcsrchr(out,L'\\');if(!p)return FALSE;*p=0;size_t len=wcslen(out);if(len+wcslen(suffix)+1>=MAX_PATH)return FALSE;wcscat(out,suffix);return TRUE;}
static BOOL loadedAt(HMODULE module,PCWSTR expected){WCHAR actual[MAX_PATH];return GetModuleFileNameW(module,actual,MAX_PATH)&&!_wcsicmp(actual,expected);}
static BOOL prepareCore(void){
 WCHAR path[MAX_PATH];initialization=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 UINT n=GetSystemDirectoryW(path,MAX_PATH);if(!n||n>MAX_PATH-40)return TRUE;wcscat(path,L"\\SystemSettings.DataModel.dll");
 if(!hashMatches(path,"f07bdc1334562d4ae3d5265e96cf44b8bfbde8388fd71e76cb698cc475703fbb"))return TRUE;
 nativeDM=LoadLibraryExW(path,NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);if(!nativeDM||!loadedAt(nativeDM,path))return TRUE;
 if(!sibling(L"\\SettingsDynamicTextCompat\\IsolatedOld\\SettingsEnvironment.Desktop.dll",path))return TRUE;
 if(!hashMatches(path,"49fbf0c1d93064813895c88da75efbaee2054394b1c1ee32612f51e712c01a4b"))return TRUE;
 oldModule=LoadLibraryExW(path,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if(!oldModule||!loadedAt(oldModule,path))return TRUE;
 HRESULT(WINAPI*get)(void**)=(void*)GetProcAddress(oldModule,"GetDesktopSettingsEnvironment");if(!get){initialization=E_NOINTERFACE;return TRUE;}
 void *provided=NULL,*queried=NULL;initialization=get(&provided);if(FAILED(initialization)||!provided){if(SUCCEEDED(initialization))initialization=E_UNEXPECTED;return TRUE;}
 initialization=((QI)(*(void***)provided)[0])(provided,&privateIID,&queried);((Release)(*(void***)provided)[2])(provided);
 if(FAILED(initialization)||!queried){if(SUCCEEDED(initialization))initialization=E_UNEXPECTED;return TRUE;}
 if((BYTE*)(*(void***)queried)[7]!=(BYTE*)oldModule+0x9f10){((Release)(*(void***)queried)[2])(queried);initialization=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);return TRUE;}
 HMODULE api=GetModuleHandleW(L"combase.dll");stringRaw=(void*)GetProcAddress(api,"WindowsGetStringRawBuffer");
 if(!stringRaw){((Release)(*(void***)queried)[2])(queried);initialization=E_NOINTERFACE;return TRUE;}
 static const GUID agileIID={0x94ea2b94,0xe9cc,0x49e0,{0xc0,0xff,0xee,0x64,0xca,0x8f,0x5b,0x90}};void*agile=NULL;
 initialization=((QI)(*(void***)queried)[0])(queried,&agileIID,&agile);
 if(FAILED(initialization)||!agile){((Release)(*(void***)queried)[2])(queried);if(SUCCEEDED(initialization))initialization=E_NOINTERFACE;return TRUE;}
 ((Release)(*(void***)agile)[2])(agile);oldEnvironment=queried;initialization=S_OK;return TRUE;
}
static BOOL CALLBACK prepare(PINIT_ONCE ignored,void*param,void**ctx){HRESULT co=CoInitializeEx(NULL,COINIT_MULTITHREADED);if(FAILED(co)&&co!=RPC_E_CHANGED_MODE){initialization=co;return TRUE;}prepareCore();if(SUCCEEDED(co))CoUninitialize();return TRUE;}
static BOOL scoped(PCWSTR s,UINT32 n){
 static PCWSTR keys[]={L"SettingsPageAbout_ControlPanelSystem",L"SettingsPageAbout",L"SettingsPageAbout_New"};
 if(!s)return FALSE;for(int i=0;i<3;i++)if(n==wcslen(keys[i])&&!wmemcmp(s,keys[i],n))return TRUE;return FALSE;
}
/* Returns actual provider HRESULT/value. No fallback substitutes success or boolean. */
__declspec(dllexport) HRESULT WINAPI SettingsCaptionQuery(void*nativeEnvironment,HS setting,BOOLEAN*value){
 if(!value)return E_POINTER;*value=FALSE;if(!nativeEnvironment)return E_POINTER;
 InitOnceExecuteOnce(&once,prepare,NULL,NULL);if(FAILED(initialization))return initialization;
 if((BYTE*)(*(void***)nativeEnvironment)[6]!=(BYTE*)nativeDM+0x16450)return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 UINT32 length=0;PCWSTR name=stringRaw(setting,&length);HRESULT hr;
 if(scoped(name,length)){hr=((QueryOld)(*(void***)oldEnvironment)[7])(oldEnvironment,name,value);InterlockedIncrement(&SettingsCaptionOldCalls);}
 else{hr=((QueryNative)(*(void***)nativeEnvironment)[6])(nativeEnvironment,setting,value);InterlockedIncrement(&SettingsCaptionNativeCalls);}
 SettingsCaptionLastResult=hr;return hr;
}
static void ReadApplicabilityLambda(void*context){
 void**lambda=context;BYTE*object=lambda[1];void*environment=*(void**)(object+0x30);HS setting=*(HS*)lambda[2];BOOLEAN*value=lambda[3];
 HRESULT hr=SettingsCaptionQuery(environment,setting,value);
 WCHAR message[256];UINT32 length=0;PCWSTR id=stringRaw?stringRaw(setting,&length):NULL;
 if(id&&length<96){swprintf(message,256,L"SettingsCaptionCompat hr=%08lx value=%u id=%.*ls",hr,value?*value:0,(int)length,id);OutputDebugStringW(message);}
 if(FAILED(hr))((void(WINAPI*)(HRESULT))(vmBase+0x100f8))(hr);
}
/* Only call during the owned process's single-threaded bootstrap, before VM consumers run. */
__declspec(dllexport) DWORD WINAPI SettingsCaptionInitialize(void*unused){
 if(hook)return 0;InitOnceExecuteOnce(&once,prepare,NULL,NULL);if(FAILED(initialization))return initialization;
 WCHAR path[MAX_PATH];if(!sibling(L"\\..\\Image\\4\\Windows\\ImmersiveControlPanel\\SystemSettingsViewModel.Desktop.dll",path))return E_FAIL;
 WCHAR canonical[MAX_PATH];if(!GetFullPathNameW(path,MAX_PATH,canonical,NULL))return HRESULT_FROM_WIN32(GetLastError());
 if(!hashMatches(canonical,"a56da88f90b9464dbfe29d792cbacf837363be8b3af3225b759ef4b9c61249c1"))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 HMODULE vm=LoadLibraryExW(canonical,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if(!vm||!loadedAt(vm,canonical))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 vmBase=(BYTE*)vm;BYTE*target=vmBase+0x4bab0;if(memcmp(target,lambdaExpected,sizeof(lambdaExpected)))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 HMODULE pin=NULL;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(PCWSTR)&ReadApplicabilityLambda,&pin))return HRESULT_FROM_WIN32(GetLastError());
 memset(installed,0x90,sizeof(installed));installed[0]=0xff;installed[1]=0x25;memset(installed+2,0,4);void*replacement=ReadApplicabilityLambda;memcpy(installed+6,&replacement,8);
 DWORD old=0,unusedProtect=0;if(!VirtualProtect(target,16,PAGE_EXECUTE_READWRITE,&old))return HRESULT_FROM_WIN32(GetLastError());
 memcpy(target,installed,16);BOOL protect=VirtualProtect(target,16,old,&unusedProtect);BOOL flush=FlushInstructionCache(GetCurrentProcess(),target,16);hook=target;
 if(!protect||!flush||memcmp(target,installed,16))return E_FAIL;
 InterlockedExchange(&SettingsCaptionInstalled,1);OutputDebugStringW(L"SettingsCaptionCompat installed exact3 old About policy keys; other native IsSettingApplicable unchanged.");return 0;
}
/* Separate fixture/controlled bootstrap restore; caller must ensure no active hook consumers. */
__declspec(dllexport) DWORD WINAPI SettingsCaptionRestore(void*unused){
 if(!hook)return 0;if(memcmp(hook,installed,16))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 DWORD old=0,tmp=0;if(!VirtualProtect(hook,16,PAGE_EXECUTE_READWRITE,&old))return HRESULT_FROM_WIN32(GetLastError());
 memcpy(hook,lambdaExpected,16);BOOL protect=VirtualProtect(hook,16,old,&tmp);BOOL flush=FlushInstructionCache(GetCurrentProcess(),hook,16);
 if(!protect||!flush||memcmp(hook,lambdaExpected,16))return E_FAIL;hook=NULL;InterlockedExchange(&SettingsCaptionInstalled,0);return 0;
}
/* Existing broker bootstrap accepts one initializer. Keep the proven initial repair chain. */
__declspec(dllexport) DWORD WINAPI SettingsInitialize(void*unused){
 WCHAR path[MAX_PATH];if(!sibling(L"\\SettingsSystemProfileCompat\\SettingsSystemProfileCompat.dll",path))return E_FAIL;
 if(!hashMatches(path,"1de372d93b15c87b7c6f4b458d33d1cae0ed6e9b291f29e1e34d3a08371dab22"))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 HMODULE base=LoadLibraryW(path);if(!base)return HRESULT_FROM_WIN32(GetLastError());DWORD(WINAPI*initialize)(void*)=(void*)GetProcAddress(base,"SettingsInitialize");
 if(!initialize)return E_NOINTERFACE;DWORD hr=initialize(NULL);if(FAILED((HRESULT)hr))return hr;return SettingsCaptionInitialize(NULL);
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD reason,void*reserved){if(reason==DLL_PROCESS_ATTACH)selfModule=h;return TRUE;}
