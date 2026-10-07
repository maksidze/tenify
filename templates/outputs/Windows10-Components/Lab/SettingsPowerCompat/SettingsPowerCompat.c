#define UNICODE
#define _UNICODE
#include <windows.h>
#include <objbase.h>
#include <winstring.h>
#include <bcrypt.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <limits.h>
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
static BOOL loadedAt(HMODULE module,PCWSTR expected){
 WCHAR mapped[4096],physical[4120],logical[MAX_PATH],message[1024];BOOL same=FALSE;
 DWORD n=K32GetMappedFileNameW(GetCurrentProcess(),module,mapped,4096);
 if(!n||n>=4096||mapped[0]!=L'\\')return FALSE;
 if(swprintf(physical,4120,L"\\\\?\\GLOBALROOT%ls",mapped)<0)return FALSE;
 HANDLE actual=CreateFileW(physical,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
 HANDLE wanted=CreateFileW(expected,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
 BY_HANDLE_FILE_INFORMATION a={0},b={0};
 if(actual!=INVALID_HANDLE_VALUE&&wanted!=INVALID_HANDLE_VALUE&&GetFileInformationByHandle(actual,&a)&&GetFileInformationByHandle(wanted,&b))same=a.dwVolumeSerialNumber==b.dwVolumeSerialNumber&&a.nFileIndexHigh==b.nFileIndexHigh&&a.nFileIndexLow==b.nFileIndexLow;
 if(actual!=INVALID_HANDLE_VALUE)CloseHandle(actual);if(wanted!=INVALID_HANDLE_VALUE)CloseHandle(wanted);
 logical[0]=0;GetModuleFileNameW(module,logical,MAX_PATH);
 swprintf(message,1024,L"SettingsCaptionCompat mapped-file identity=%d module=%p volume=%08lx file=%08lx%08lx logical=%ls mapped=%ls",same,module,a.dwVolumeSerialNumber,a.nFileIndexHigh,a.nFileIndexLow,logical,mapped);OutputDebugStringW(message);
 return same;
}

static const WCHAR vmPath[]=L"@WORKSPACE_ESC@\\outputs\\Windows10-Components\\Image\\4\\Windows\\ImmersiveControlPanel\\SystemSettingsViewModel.Desktop.dll";
static const WCHAR providerPath[]=L"@WORKSPACE_ESC@\\outputs\\Windows10-Components\\Image\\4\\Windows\\System32\\SettingsHandlers_OneCore_PowerAndSleep.dll";
static const char vmHash[]="a56da88f90b9464dbfe29d792cbacf837363be8b3af3225b759ef4b9c61249c1";
static const char providerHash[]="9ac1f9c879fe5204c8b96f14cbed19ffb004f25bcf88d982979e42f27cf394e6";
typedef struct {DWORD rva;BYTE original[5],patched[5];} CallGuard;
static CallGuard guards[4]={{0x240ae,{0xe8,0x61,0x3c,0xff,0xff}},{0x243ad,{0xe8,0x62,0x39,0xff,0xff}},{0x24513,{0xe8,0xac,0x1b,0xfe,0xff}},{0x24834,{0xe8,0x8b,0x18,0xfe,0xff}}};

typedef HRESULT(WINAPI *NativeGet)(void*,HSTRING,void**);
typedef HRESULT(WINAPI *NativeUserGet)(void*,void*,HSTRING,void**);
typedef HRESULT(WINAPI *ProviderGet)(HSTRING,void**);
typedef void*(WINAPI *Projection)(void*,HSTRING);
typedef void*(WINAPI *UserProjection)(void*,void*,HSTRING);
static HMODULE vm,provider;static ProviderGet providerGet;static BYTE*thunks;static SRWLOCK lock=SRWLOCK_INIT;
__declspec(dllexport) volatile LONG PowerInstalled,PowerFallbackCalls,PowerNativeCalls;
__declspec(dllexport) volatile HRESULT PowerLastResult;
static PCWSTR keys[]={L"SystemSettings_PowerAndSleep_DisplayOffTimeoutAC",L"SystemSettings_PowerAndSleep_DisplayOffTimeoutDC",L"SystemSettings_PowerAndSleep_SleepTimeoutAC",L"SystemSettings_PowerAndSleep_SleepTimeoutDC"};
static BOOL exact(HSTRING key){UINT32 count=0;PCWSTR(WINAPI*raw)(HSTRING,UINT32*)=(void*)GetProcAddress(GetModuleHandleW(L"combase.dll"),"WindowsGetStringRawBuffer");if(!raw)return FALSE;PCWSTR text=raw(key,&count);for(int i=0;i<4;i++)if(count==wcslen(keys[i])&&!wmemcmp(text,keys[i],count))return TRUE;return FALSE;}
static void release(void*p){if(p)((ULONG(WINAPI*)(void*))(*(void***)p)[2])(p);}
static HRESULT fallback(HSTRING key,void**out){HRESULT hr=providerGet(key,out);if(FAILED(hr)){release(*out);*out=NULL;}else{
 static const GUID iid={0x40c037cc,0xd8bf,0x489e,{0x86,0x97,0xd6,0x6b,0xaa,0x32,0x21,0xbf}};void*q=NULL;
 if(!*out)return E_UNEXPECTED;hr=((HRESULT(WINAPI*)(void*,REFIID,void**))(*(void***)*out)[0])(*out,&iid,&q);release(q);
 if(FAILED(hr)){release(*out);*out=NULL;}}
 InterlockedIncrement(&PowerFallbackCalls);return hr;}
__declspec(dllexport) HRESULT WINAPI SettingsPowerQuery(void*db,HSTRING key,void**out){
 if(!db||!out)return E_POINTER;*out=NULL;HRESULT hr=((NativeGet)(*(void***)db)[6])(db,key,out);InterlockedIncrement(&PowerNativeCalls);
 if(hr==HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)&&exact(key)){release(*out);*out=NULL;if(!providerGet)return E_UNEXPECTED;hr=fallback(key,out);}PowerLastResult=hr;return hr;}
__declspec(dllexport) HRESULT WINAPI SettingsPowerQueryForUser(void*db,void*user,HSTRING key,void**out){
 if(!db||!out)return E_POINTER;*out=NULL;HRESULT hr=((NativeUserGet)(*(void***)db)[6])(db,user,key,out);InterlockedIncrement(&PowerNativeCalls);
 if(hr==HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)&&exact(key)){release(*out);*out=NULL;if(!providerGet)return E_UNEXPECTED;hr=fallback(key,out);}PowerLastResult=hr;return hr;}
__declspec(dllexport) void*WINAPI SettingsPowerProject(void*db,HSTRING key){
 if(!exact(key))return ((Projection)((BYTE*)vm+0x17d14))(db,key);void*out=NULL;HRESULT hr=SettingsPowerQuery(db,key,&out);
 if(FAILED(hr)){release(out);((void(WINAPI*)(HRESULT))((BYTE*)vm+0x100f8))(hr);return NULL;}return out;}
__declspec(dllexport) void*WINAPI SettingsPowerProjectForUser(void*db,void*user,HSTRING key){
 if(!exact(key))return ((UserProjection)((BYTE*)vm+0x60c4))(db,user,key);void*out=NULL;HRESULT hr=SettingsPowerQueryForUser(db,user,key,&out);
 if(FAILED(hr)){release(out);((void(WINAPI*)(HRESULT))((BYTE*)vm+0x100f8))(hr);return NULL;}return out;}
__declspec(dllexport) DWORD WINAPI SettingsPowerPrepare(void*unused){
 (void)unused;if(providerGet)return 0;if(!hashMatches(providerPath,providerHash))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 provider=LoadLibraryExW(providerPath,NULL,LOAD_WITH_ALTERED_SEARCH_PATH);if(!provider||!loadedAt(provider,providerPath))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 providerGet=(ProviderGet)GetProcAddress(provider,"GetSetting");return providerGet?0:E_NOINTERFACE;}
static BOOL write(void*at,const BYTE*bytes,SIZE_T size){DWORD old,ignored;if(!VirtualProtect(at,size,PAGE_EXECUTE_READWRITE,&old))return FALSE;memcpy(at,bytes,size);FlushInstructionCache(GetCurrentProcess(),at,size);return VirtualProtect(at,size,old,&ignored);}
__declspec(dllexport) DWORD WINAPI SettingsPowerInitialize(void*unused){
 AcquireSRWLockExclusive(&lock);DWORD hr=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);if(PowerInstalled){hr=0;goto end;}
 hr=SettingsPowerPrepare(unused);if(hr)goto end;hr=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);vm=GetModuleHandleW(L"SystemSettingsViewModel.Desktop.dll");
 if(!vm||!hashMatches(vmPath,vmHash)||!loadedAt(vm,vmPath))goto end;
 for(int i=0;i<4;i++)if(memcmp((BYTE*)vm+guards[i].rva,guards[i].original,5))goto end;
 SYSTEM_INFO info;GetSystemInfo(&info);ULONGLONG start=((ULONGLONG)vm+0x100000+info.dwAllocationGranularity-1)&~((ULONGLONG)info.dwAllocationGranularity-1);
 for(ULONGLONG at=start;at<(ULONGLONG)vm+0x70000000;at+=info.dwAllocationGranularity){thunks=VirtualAlloc((void*)at,32,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(thunks)break;}
 if(!thunks){hr=E_OUTOFMEMORY;goto end;}
 for(int n=0;n<2;n++){BYTE*b=thunks+16*n;b[0]=0xff;b[1]=0x25;memset(b+2,0,4);void*fn=n?(void*)SettingsPowerProjectForUser:(void*)SettingsPowerProject;memcpy(b+6,&fn,8);}
 DWORD old;if(!VirtualProtect(thunks,32,PAGE_EXECUTE_READ,&old)){hr=HRESULT_FROM_WIN32(GetLastError());goto end;}FlushInstructionCache(GetCurrentProcess(),thunks,32);
 for(int i=0;i<4;i++){BYTE*at=(BYTE*)vm+guards[i].rva;LONGLONG distance=(thunks+(i>=2?16:0))-(at+5);if(distance<INT_MIN||distance>INT_MAX){hr=E_FAIL;goto end;}guards[i].patched[0]=0xe8;INT32 relative=(INT32)distance;memcpy(guards[i].patched+1,&relative,4);}
 for(int i=0;i<4;i++)if(!write((BYTE*)vm+guards[i].rva,guards[i].patched,5)){hr=HRESULT_FROM_WIN32(GetLastError());for(int j=0;j<=i;j++)write((BYTE*)vm+guards[j].rva,guards[j].original,5);goto end;}
 PowerInstalled=1;hr=0;
 end:PowerLastResult=hr;ReleaseSRWLockExclusive(&lock);return hr;}
__declspec(dllexport) DWORD WINAPI SettingsPowerRestore(void*unused){
 (void)unused;AcquireSRWLockExclusive(&lock);DWORD hr=0;if(PowerInstalled){for(int i=0;i<4;i++)if(memcmp((BYTE*)vm+guards[i].rva,guards[i].patched,5)){hr=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);goto end;}
 for(int i=0;i<4;i++)if(!write((BYTE*)vm+guards[i].rva,guards[i].original,5)){hr=HRESULT_FROM_WIN32(GetLastError());goto end;}PowerInstalled=0;}
 end:ReleaseSRWLockExclusive(&lock);return hr;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD why,LPVOID reserved){(void)reserved;if(why==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(h);return TRUE;}
