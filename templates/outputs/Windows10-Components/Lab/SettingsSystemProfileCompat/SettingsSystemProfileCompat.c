#include <windows.h>
#include <objbase.h>
#include <stdio.h>
#include <bcrypt.h>
#include <string.h>
static BOOL verifyHash(const WCHAR *path){
 BYTE expected[]={0x7a,0x2f,0xb4,0xf7,0x93,0x3a,0x8d,0x74,0x70,0x8a,0x4b,0x78,0x08,0x5b,0x7c,0x67,0x33,0x2f,0xaf,0xcc,0x9c,0xd5,0xc3,0xd2,0xd2,0x40,0xbf,0xf4,0x04,0xc4,0xb5,0x44},digest[32],buffer[65536];
 BCRYPT_ALG_HANDLE algorithm=NULL;BCRYPT_HASH_HANDLE hash=NULL;BYTE *object=NULL;DWORD length=0,used=0,bytes=0;BOOL ok=FALSE;
 HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);if(file==INVALID_HANDLE_VALUE)return FALSE;
 if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto end;
 if(BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,(BYTE*)&length,sizeof(length),&used,0)<0)goto end;
 object=HeapAlloc(GetProcessHeap(),0,length);if(!object)goto end;
 if(BCryptCreateHash(algorithm,&hash,object,length,NULL,0,0)<0)goto end;
 for(;;){if(!ReadFile(file,buffer,sizeof(buffer),&bytes,NULL))goto end;if(!bytes)break;if(BCryptHashData(hash,buffer,bytes,0)<0)goto end;}
 if(BCryptFinishHash(hash,digest,sizeof(digest),0)<0)goto end;
 ok=!memcmp(digest,expected,sizeof(expected));
end: if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);if(object)HeapFree(GetProcessHeap(),0,object);CloseHandle(file);return ok;
}

static BOOL verifyOldHash(const WCHAR *path){
 BYTE expected[]={0x64,0xfb,0x91,0x89,0x5b,0x76,0x20,0x9d,0x47,0x85,0x06,0x02,0x49,0x47,0x1c,0xba,0x89,0x7e,0x00,0xec,0x89,0xc2,0x73,0x22,0x7a,0xe1,0xba,0x62,0x07,0x15,0x51,0x5a},digest[32],buffer[65536];
 BCRYPT_ALG_HANDLE algorithm=NULL;BCRYPT_HASH_HANDLE hash=NULL;BYTE *object=NULL;DWORD length=0,used=0,bytes=0;BOOL ok=FALSE;
 HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);if(file==INVALID_HANDLE_VALUE)return FALSE;
 if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto end;
 if(BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,(BYTE*)&length,sizeof(length),&used,0)<0)goto end;
 object=HeapAlloc(GetProcessHeap(),0,length);if(!object)goto end;
 if(BCryptCreateHash(algorithm,&hash,object,length,NULL,0,0)<0)goto end;
 for(;;){if(!ReadFile(file,buffer,sizeof(buffer),&bytes,NULL))goto end;if(!bytes)break;if(BCryptHashData(hash,buffer,bytes,0)<0)goto end;}
 if(BCryptFinishHash(hash,digest,sizeof(digest),0)<0)goto end;
 ok=!memcmp(digest,expected,sizeof(expected));
end: if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);if(object)HeapFree(GetProcessHeap(),0,object);CloseHandle(file);return ok;
}

static BOOL verifyVmHash(const WCHAR *path){
 BYTE expected[]={0xa5,0x6d,0xa8,0x8f,0x90,0xb9,0x46,0x4d,0xbf,0xe2,0x9d,0x79,0x2c,0xba,0xcf,0x83,0x73,0x63,0xbe,0x8b,0x3a,0xf3,0x22,0x5b,0x75,0x9e,0xf4,0xb9,0xc6,0x12,0x49,0xc1},digest[32],buffer[65536];
 BCRYPT_ALG_HANDLE algorithm=NULL;BCRYPT_HASH_HANDLE hash=NULL;BYTE *object=NULL;DWORD length=0,used=0,bytes=0;BOOL ok=FALSE;
 HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);if(file==INVALID_HANDLE_VALUE)return FALSE;
 if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto end;
 if(BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,(BYTE*)&length,sizeof(length),&used,0)<0)goto end;
 object=HeapAlloc(GetProcessHeap(),0,length);if(!object)goto end;
 if(BCryptCreateHash(algorithm,&hash,object,length,NULL,0,0)<0)goto end;
 for(;;){if(!ReadFile(file,buffer,sizeof(buffer),&bytes,NULL))goto end;if(!bytes)break;if(BCryptHashData(hash,buffer,bytes,0)<0)goto end;}
 if(BCryptFinishHash(hash,digest,sizeof(digest),0)<0)goto end;
 ok=!memcmp(digest,expected,sizeof(expected));
end: if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);if(object)HeapFree(GetProcessHeap(),0,object);CloseHandle(file);return ok;
}

static BOOL verifyNativeDataModelHash(const WCHAR *path){
 BYTE expected[]={0xf0,0x7b,0xdc,0x13,0x34,0x56,0x2d,0x4a,0xe3,0xd5,0x26,0x5e,0x96,0xcf,0x44,0xb8,0xbf,0xbd,0xe8,0x38,0x8f,0xd7,0x1e,0x76,0xcb,0x69,0x8c,0xc4,0x75,0x70,0x3f,0xbb},digest[32],buffer[65536];
 BCRYPT_ALG_HANDLE algorithm=NULL;BCRYPT_HASH_HANDLE hash=NULL;BYTE *object=NULL;DWORD length=0,used=0,bytes=0;BOOL ok=FALSE;
 HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);if(file==INVALID_HANDLE_VALUE)return FALSE;
 if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto end;
 if(BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,(BYTE*)&length,sizeof(length),&used,0)<0)goto end;
 object=HeapAlloc(GetProcessHeap(),0,length);if(!object)goto end;
 if(BCryptCreateHash(algorithm,&hash,object,length,NULL,0,0)<0)goto end;
 for(;;){if(!ReadFile(file,buffer,sizeof(buffer),&bytes,NULL))goto end;if(!bytes)break;if(BCryptHashData(hash,buffer,bytes,0)<0)goto end;}
 if(BCryptFinishHash(hash,digest,sizeof(digest),0)<0)goto end;
 ok=!memcmp(digest,expected,sizeof(expected));
end: if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);if(object)HeapFree(GetProcessHeap(),0,object);CloseHandle(file);return ok;
}


static BOOL verifyOldEnvironmentHash(const WCHAR *path){
 BYTE expected[]={0x49,0xfb,0xf0,0xc1,0xd9,0x30,0x64,0x81,0x38,0x95,0xc8,0x8d,0xa7,0x5e,0xfb,0xae,0xe2,0x05,0x43,0x94,0xb1,0xc1,0xee,0x32,0x61,0x2f,0x51,0xe7,0x12,0xc0,0x1a,0x4b},digest[32],buffer[65536];
 BCRYPT_ALG_HANDLE algorithm=NULL;BCRYPT_HASH_HANDLE hash=NULL;BYTE *object=NULL;DWORD length=0,used=0,bytes=0;BOOL ok=FALSE;
 HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);if(file==INVALID_HANDLE_VALUE)return FALSE;
 if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto end;
 if(BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,(BYTE*)&length,sizeof(length),&used,0)<0)goto end;
 object=HeapAlloc(GetProcessHeap(),0,length);if(!object)goto end;
 if(BCryptCreateHash(algorithm,&hash,object,length,NULL,0,0)<0)goto end;
 for(;;){if(!ReadFile(file,buffer,sizeof(buffer),&bytes,NULL))goto end;if(!bytes)break;if(BCryptHashData(hash,buffer,bytes,0)<0)goto end;}
 if(BCryptFinishHash(hash,digest,sizeof(digest),0)<0)goto end;
 ok=!memcmp(digest,expected,sizeof(expected));
end: if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);if(object)HeapFree(GetProcessHeap(),0,object);CloseHandle(file);return ok;
}


static INIT_ONCE oldEnvironmentOnce=INIT_ONCE_STATIC_INIT;static void*oldEnvironment;static HRESULT oldEnvironmentInit=E_UNEXPECTED;static HMODULE oldEnvironmentModule;
static BOOL CALLBACK initializeOldEnvironment(PINIT_ONCE unused,void*parameter,void**context){
 WCHAR path[]=L"@WORKSPACE_ESC@\\outputs\\Windows10-Components\\Lab\\SettingsDynamicTextCompat\\IsolatedOld\\SettingsEnvironment.Desktop.dll";if(!verifyOldEnvironmentHash(path)){oldEnvironmentInit=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);return TRUE;}
 oldEnvironmentModule=LoadLibraryExW(path,NULL,LOAD_WITH_ALTERED_SEARCH_PATH);if(!oldEnvironmentModule){oldEnvironmentInit=HRESULT_FROM_WIN32(GetLastError());return TRUE;}
 HRESULT(WINAPI*get)(void**)=(void*)GetProcAddress(oldEnvironmentModule,"GetDesktopSettingsEnvironment");oldEnvironmentInit=get?get(&oldEnvironment):E_NOINTERFACE;return TRUE;
}
static BYTE*settingsVmBase;
__declspec(dllexport) volatile HRESULT SettingsDynamicTextLastResult;
__declspec(dllexport) volatile LONG SettingsDynamicTextCalls;
static void ReadDynamicText(void*context){
 void**lambda=context;BYTE*object=lambda[1];void*environment=*(void**)(object+0x30);void*setting=*(void**)lambda[2];BOOLEAN*value=lambda[3];
 if(value)*value=FALSE;
 HRESULT hr=((HRESULT(WINAPI*)(void*,void*,BOOLEAN*))(*(void***)environment)[8])(environment,setting,value);

 HRESULT nativeResult=hr;
 if(hr==(HRESULT)0x8002802b){
  UINT32 oldLength=0;PCWSTR(WINAPI*readString)(void*,UINT32*)=(void*)GetProcAddress(GetModuleHandleW(L"combase.dll"),"WindowsGetStringRawBuffer");PCWSTR oldName=readString?readString(setting,&oldLength):NULL;
  if(oldName&&oldLength<=256&&!wcsncmp(oldName,L"Settings",8)){
   InitOnceExecuteOnce(&oldEnvironmentOnce,initializeOldEnvironment,NULL,NULL);
   if(SUCCEEDED(oldEnvironmentInit)&&oldEnvironment)hr=((HRESULT(WINAPI*)(void*,LPCWSTR,BOOLEAN*))(*(void***)oldEnvironment)[9])(oldEnvironment,oldName,value);else hr=oldEnvironmentInit;
   WCHAR note[512];swprintf(note,512,L"SettingsDynamicTextCompat genuine fallback native=%08lx old=%08lx value=%u id=%.*ls",nativeResult,hr,value?*value:0,(int)oldLength,oldName);OutputDebugStringW(note);
  }
 }
 SettingsDynamicTextLastResult=hr;InterlockedIncrement(&SettingsDynamicTextCalls);
 UINT32 length=0;PCWSTR(WINAPI*raw)(void*,UINT32*)=(void*)GetProcAddress(GetModuleHandleW(L"combase.dll"),"WindowsGetStringRawBuffer");PCWSTR name=raw?raw(setting,&length):NULL;
 WCHAR message[512];if(name&&length<256&&!wcsncmp(name,L"Settings",8))swprintf(message,512,L"SettingsDynamicTextCompat tid=%lu hr=%08lx id=%.*ls",GetCurrentThreadId(),hr,(int)length,name);else swprintf(message,512,L"SettingsDynamicTextCompat tid=%lu hr=%08lx stringLength=%u",GetCurrentThreadId(),hr,length);OutputDebugStringW(message);
 if(FAILED(hr))((void(WINAPI*)(HRESULT))(settingsVmBase+0x100f8))(hr);
}
static const GUID clsid={0xdbce7e40,0x7345,0x439d,{0xb1,0x2c,0x11,0x4a,0x11,0x81,0x9a,0x09}};
static const GUID iid={0x130a2f65,0x2be7,0x4309,{0x9a,0x58,0xa9,0x05,0x2f,0xf2,0xb6,0x1c}};
static WCHAR indexFile[]=L"@WORKSPACE_ESC@\\outputs\\Windows10-Components\\Image\\4\\Windows\\SystemResources\\Windows.UI.SettingsAppThreshold\\Windows.UI.SettingsAppThreshold.pri";
__declspec(dllexport) volatile LONG SettingsMrtCalls;
__declspec(dllexport) volatile HRESULT SettingsMrtLastResult;
static BYTE *patched;static BYTE original[14];
static HRESULT WINAPI CreateOwnFileMrt(void**out){
 if(!out)return E_POINTER;*out=NULL;void*manager=NULL;
 HRESULT hr=CoCreateInstance(&clsid,NULL,CLSCTX_INPROC_SERVER,&iid,&manager);
 if(SUCCEEDED(hr)&&manager){hr=((HRESULT(WINAPI*)(void*,LPCWSTR))(*(void***)manager)[6])(manager,indexFile);
  if(SUCCEEDED(hr)){*out=manager;manager=NULL;}}
 if(manager)((ULONG(WINAPI*)(void*))(*(void***)manager)[2])(manager);
 InterlockedIncrement(&SettingsMrtCalls);SettingsMrtLastResult=hr;WCHAR message[256];swprintf(message,256,L"SettingsMrtCompat actual native CoCreate+InitializeForFile hr=%08lx output=%p",hr,*out);OutputDebugStringW(message);return hr;
}

static HANDLE profileReady,profileKeepAlive,profileThread;static HRESULT profileResult=E_PENDING;
static DWORD WINAPI retainSystemProfile(void*unused){
 HMODULE api=LoadLibraryW(L"combase.dll");HRESULT(WINAPI*initialize)(int)=(void*)GetProcAddress(api,"RoInitialize");HRESULT(WINAPI*make)(PCWSTR,UINT32,void**)=(void*)GetProcAddress(api,"WindowsCreateString");HRESULT(WINAPI*factory)(void*,const GUID*,void**)=(void*)GetProcAddress(api,"RoGetActivationFactory");
 GUID statics={0x4a8eac58,0xb652,0x459d,{0x8d,0xe1,0x23,0x94,0x71,0xe8,0xb2,0x2b}},ext={0x8c25e859,0x1042,0x4da0,{0x92,0x32,0xbf,0x2a,0xa8,0xff,0x37,0x26}};void*s=0,*f=0,*manager=0,*extension=0;HRESULT hr=initialize(1);if(FAILED(hr))goto done;
 PCWSTR cls=L"Windows.ApplicationModel.Resources.Core.ResourceManager";hr=make(cls,lstrlenW(cls),&s);if(FAILED(hr))goto done;hr=factory(s,&statics,&f);if(FAILED(hr))goto done;hr=((HRESULT(WINAPI*)(void*,void**))(*(void***)f)[7])(f,&manager);if(FAILED(hr))goto done;hr=((HRESULT(WINAPI*)(void*,const GUID*,void**))(*(void***)manager)[0])(manager,&ext,&extension);if(FAILED(hr))goto done;hr=((HRESULT(WINAPI*)(void*,PCWSTR))(*(void***)extension)[6])(extension,indexFile);
 done:profileResult=hr;WCHAR message[160];swprintf(message,160,L"SettingsSystemProfileCompat retained MTA LoadPriFileForSystemUse=%08lx thread=%lu",hr,GetCurrentThreadId());OutputDebugStringW(message);SetEvent(profileReady);
 // Retain the apartment and genuine manager references until this owned process exits.
 WaitForSingleObject(profileKeepAlive,INFINITE);return hr;
}
__declspec(dllexport) HRESULT WINAPI SettingsSystemProfileResult(void*unused){return profileResult;}
static HRESULT prepareSystemProfile(void){if(profileThread)return profileResult;profileReady=CreateEventW(NULL,TRUE,FALSE,NULL);profileKeepAlive=CreateEventW(NULL,TRUE,FALSE,NULL);if(!profileReady||!profileKeepAlive)return HRESULT_FROM_WIN32(GetLastError());profileThread=CreateThread(NULL,0,retainSystemProfile,NULL,0,NULL);if(!profileThread)return HRESULT_FROM_WIN32(GetLastError());return WaitForSingleObject(profileReady,15000)==WAIT_OBJECT_0?profileResult:HRESULT_FROM_WIN32(ERROR_TIMEOUT);}
__declspec(dllexport) volatile LONG SettingsSystemProfileStage;
__declspec(dllexport) DWORD WINAPI SettingsInitialize(void*unused){
 (void)unused;if(patched)return 0;
 WCHAR path[MAX_PATH];UINT n=GetSystemDirectoryW(path,MAX_PATH);if(!n||n>MAX_PATH-24)return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);wcscat(path,L"\\Windows.UI.Xaml.dll");
 SettingsSystemProfileStage=1;
 if(!verifyHash(path))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 HMODULE module=LoadLibraryW(path);if(!module)return HRESULT_FROM_WIN32(GetLastError());BYTE*base=(BYTE*)module;
 SettingsSystemProfileStage=2;
 BYTE expected[]={0x48,0x89,0x5c,0x24,0x18,0x55,0x56,0x57,0x48,0x8b,0xec,0x48,0x83,0xec,0x30,0x48,0x83,0x21,0x00,0x48,0x8b,0xf1,0x48,0x83};if(memcmp(base+0x5242b8,expected,sizeof(expected)))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 SettingsSystemProfileStage=3;
 if(!verifyOldHash(indexFile))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 SettingsSystemProfileStage=4;
 HRESULT profileHr=prepareSystemProfile();if(FAILED(profileHr))return profileHr;

 WCHAR vmPath[]=L"@WORKSPACE_ESC@\\outputs\\Windows10-Components\\Image\\4\\Windows\\ImmersiveControlPanel\\SystemSettingsViewModel.Desktop.dll"; WCHAR dmPath[MAX_PATH];UINT length=GetSystemDirectoryW(dmPath,MAX_PATH);if(!length||length>MAX_PATH-40)return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);wcscat(dmPath,L"\\SystemSettings.DataModel.dll");
 SettingsSystemProfileStage=5;
 if(!verifyVmHash(vmPath)||!verifyNativeDataModelHash(dmPath))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 SettingsSystemProfileStage=6;
 HMODULE vm=LoadLibraryExW(vmPath,NULL,LOAD_WITH_ALTERED_SEARCH_PATH);if(!vm)return HRESULT_FROM_WIN32(GetLastError());
 BYTE *vmBase=(BYTE*)vm;static const BYTE callBytes[]={0x48,0x8b,0x42,0x48,0x4c,0x8d,0x45,0xd0,0x48,0x8b,0xd7,0x48,0x8b,0xcb};
 if(memcmp(vmBase+0x4b0e4,callBytes,sizeof(callBytes)))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 DWORD vmProtect=0,vmUnused=0;if(!VirtualProtect(vmBase+0x4b0e7,1,PAGE_EXECUTE_READWRITE,&vmProtect))return HRESULT_FROM_WIN32(GetLastError());
 vmBase[0x4b0e7]=0x50;VirtualProtect(vmBase+0x4b0e7,1,vmProtect,&vmUnused);FlushInstructionCache(GetCurrentProcess(),vmBase+0x4b0e7,1);
 OutputDebugStringW(L"SettingsEnvironmentCompat verified old add_SettingsEnvironmentChanged slot9->native10, same delegate IID; genuine host call, no substituted result.");
 settingsVmBase=vmBase;static const BYTE lambdaGuard[]={0x48,0x83,0xec,0x28,0x48,0x8b,0x41,0x08,0x4c,0x8b,0x41,0x18,0x4c,0x8b,0x48,0x30};if(memcmp(vmBase+0x4b990,lambdaGuard,16))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 BYTE lambdaPatch[14]={0xff,0x25,0,0,0,0};void*lambdaReplacement=ReadDynamicText;memcpy(lambdaPatch+6,&lambdaReplacement,8);if(!VirtualProtect(vmBase+0x4b990,14,PAGE_EXECUTE_READWRITE,&vmProtect))return HRESULT_FROM_WIN32(GetLastError());memcpy(vmBase+0x4b990,lambdaPatch,14);VirtualProtect(vmBase+0x4b990,14,vmProtect,&vmUnused);FlushInstructionCache(GetCurrentProcess(),vmBase+0x4b990,14);
 OutputDebugStringW(L"SettingsDynamicTextCompat verified own oldVM lambda wrapper passes native slot8 args/result and genuine old WinRTraise on failure; traces only system Settings IDs.");

 HANDLE file=CreateFileW(indexFile,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);if(file==INVALID_HANDLE_VALUE)return HRESULT_FROM_WIN32(GetLastError());CloseHandle(file);
 BYTE*target=base+0x5242b8;BYTE patch[14]={0xff,0x25,0,0,0,0};void*function=CreateOwnFileMrt;memcpy(patch+6,&function,8);DWORD old=0,unusedProtect=0;if(!VirtualProtect(target,sizeof(patch),PAGE_EXECUTE_READWRITE,&old))return HRESULT_FROM_WIN32(GetLastError());
 memcpy(original,target,sizeof(original));memcpy(target,patch,sizeof(patch));VirtualProtect(target,sizeof(patch),old,&unusedProtect);FlushInstructionCache(GetCurrentProcess(),target,sizeof(patch));patched=target;
 OutputDebugStringW(L"SettingsMrtCompat installed only native ModernResourceProvider current-application factory route to explicit old PRI file; genuine native IMrt manager.");return 0;
}
__declspec(dllexport) DWORD WINAPI SettingsMrtRestore(void*unused){(void)unused;if(!patched)return 0;DWORD old=0,unusedProtect=0;if(!VirtualProtect(patched,14,PAGE_EXECUTE_READWRITE,&old))return HRESULT_FROM_WIN32(GetLastError());memcpy(patched,original,14);VirtualProtect(patched,14,old,&unusedProtect);FlushInstructionCache(GetCurrentProcess(),patched,14);patched=NULL;return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID p){return TRUE;}
