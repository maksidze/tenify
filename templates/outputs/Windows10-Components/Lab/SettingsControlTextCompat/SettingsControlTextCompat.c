#define UNICODE
#define _UNICODE
#include <windows.h>
#include <objbase.h>
#include <bcrypt.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdint.h>
#include "DescriptionCallsite.h"
typedef void* HS;
typedef HRESULT(WINAPI* QIFn)(void*,REFIID,void**);
typedef ULONG(WINAPI* ReleaseFn)(void*);
typedef HRESULT(WINAPI* PtrFn)(void*,void**);
typedef HRESULT(WINAPI* QueryFn)(void*,HS,void**);
typedef HRESULT(WINAPI* LoadPriFn)(void*,PCWSTR);
static const GUID itemIID={0x40c037cc,0xd8bf,0x489e,{0x86,0x97,0xd6,0x6b,0xaa,0x32,0x21,0xbf}};
static const GUID resourceStatics={0x4a8eac58,0xb652,0x459d,{0x8d,0xe1,0x23,0x94,0x71,0xe8,0xb2,0x2b}};
static const GUID resourceExt={0x8c25e859,0x1042,0x4da0,{0x92,0x32,0xbf,0x2a,0xa8,0xff,0x37,0x26}};
static PCWSTR keys[]={L"SystemSettings_Taskbar_Lock",L"SystemSettings_Taskbar_Autohide",L"SystemSettings_Taskbar_SmallButtons",L"SystemSettings_Taskbar_Badging",L"SystemSettings_Taskbar_Location",L"SystemSettings_Taskbar_GlommingPrimary",L"SystemSettings_Taskbar_PeekPreviewDesktop",L"SystemSettings_Taskbar_ReplaceCommandPromptWithPowerShellWinX",L"SystemSettings_ShellMode_TaskbarTabletModeAutohide"};
static HMODULE selfModule,vmModule;
static BYTE *hook,*trampoline;static BYTE installed[5];
static HRESULT installStatus=E_PENDING;
static WCHAR priPath[4096],vmPath[4096];
static INIT_ONCE once=INIT_ONCE_STATIC_INIT;static HRESULT preparation=E_PENDING;
static HRESULT(WINAPI*makeString)(PCWSTR,UINT32,HS*);
static HRESULT(WINAPI*deleteString)(HS);
static PCWSTR(WINAPI*rawString)(HS,UINT32*);
static HRESULT(WINAPI*factoryFor)(HS,REFIID,void**);
__declspec(dllexport) volatile LONG SettingsControlTextInstalled,SettingsControlTextNativeCalls,SettingsControlTextFallbackCalls,SettingsControlTextFailures;
__declspec(dllexport) volatile HRESULT SettingsControlTextLastResult;
static void drop(void**p){if(*p){((ReleaseFn)(*(void***)(*p))[2])(*p);*p=NULL;}}
static BOOL hashMatches(PCWSTR path,const char*hex){
 BYTE digest[32],buffer[65536],*object=NULL;BCRYPT_ALG_HANDLE alg=NULL;BCRYPT_HASH_HANDLE hash=NULL;DWORD size=0,used=0,read=0;BOOL ok=FALSE;
 HANDLE f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);if(f==INVALID_HANDLE_VALUE)return FALSE;
 if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto done;
 if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(BYTE*)&size,4,&used,0)<0)goto done;
 object=HeapAlloc(GetProcessHeap(),0,size);if(!object)goto done;
 if(BCryptCreateHash(alg,&hash,object,size,NULL,0,0)<0)goto done;
 for(;;){if(!ReadFile(f,buffer,sizeof(buffer),&read,NULL))goto done;if(!read)break;if(BCryptHashData(hash,buffer,read,0)<0)goto done;}
 if(BCryptFinishHash(hash,digest,32,0)<0)goto done;ok=TRUE;
 for(int i=0;i<32;i++){char x[3]={hex[2*i],hex[2*i+1],0};if(digest[i]!=(BYTE)strtoul(x,NULL,16)){ok=FALSE;break;}}
 done:if(hash)BCryptDestroyHash(hash);if(alg)BCryptCloseAlgorithmProvider(alg,0);if(object)HeapFree(GetProcessHeap(),0,object);CloseHandle(f);return ok;
}
static BOOL relativePath(PCWSTR suffix,PWSTR output){WCHAR path[4096];DWORD n=GetModuleFileNameW(selfModule,path,4096);if(!n||n>=4096)return FALSE;WCHAR*end=wcsrchr(path,L'\\');if(!end)return FALSE;end[1]=0;if(wcslen(path)+wcslen(suffix)>=4096)return FALSE;wcscat(path,suffix);n=GetFullPathNameW(path,4096,output,NULL);return n&&n<4096;}
/* VFS changes GetModuleFileName; check the kernel image-section backing file. */
static BOOL loadedAt(HMODULE module,PCWSTR expected){WCHAR mapped[4096],path[4120];DWORD n=K32GetMappedFileNameW(GetCurrentProcess(),module,mapped,4096);if(!n||n>=4096||mapped[0]!=L'\\')return FALSE;if(swprintf(path,4120,L"\\\\?\\GLOBALROOT%ls",mapped)<0)return FALSE;
 HANDLE a=CreateFileW(path,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL),b=CreateFileW(expected,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);BY_HANDLE_FILE_INFORMATION x={0},y={0};BOOL same=FALSE;
 if(a!=INVALID_HANDLE_VALUE&&b!=INVALID_HANDLE_VALUE&&GetFileInformationByHandle(a,&x)&&GetFileInformationByHandle(b,&y))same=x.dwVolumeSerialNumber==y.dwVolumeSerialNumber&&x.nFileIndexHigh==y.nFileIndexHigh&&x.nFileIndexLow==y.nFileIndexLow;
 if(a!=INVALID_HANDLE_VALUE)CloseHandle(a);if(b!=INVALID_HANDLE_VALUE)CloseHandle(b);return same;
}
static BOOL CALLBACK prepare(PINIT_ONCE ignored,void*parameter,void**context){
 preparation=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);WCHAR path[4096];
 if(!relativePath(L"..\\..\\Image\\4\\Windows\\ImmersiveControlPanel\\SystemSettingsViewModel.Desktop.dll",vmPath)||!hashMatches(vmPath,"a56da88f90b9464dbfe29d792cbacf837363be8b3af3225b759ef4b9c61249c1"))return TRUE;
 if(!relativePath(L"..\\..\\Image\\4\\Windows\\SystemResources\\Windows.UI.SettingsHandlers-nt\\Windows.UI.SettingsHandlers-nt.pri",priPath)||!hashMatches(priPath,"f03e22b4d7131012a88b43ac39ee2fa01a876bed3db9d84e8d93136736ac1f51"))return TRUE;
 if(!relativePath(L"..\\..\\Image\\4\\Windows\\SystemResources\\Windows.UI.SettingsHandlers-nt\\pris\\Windows.UI.SettingsHandlers-nt.ru-RU.pri",path)||!hashMatches(path,"786267b3b2f4e2e7a7fcfc9684871f38764dfb674f514e8e839c324b972b79ad"))return TRUE;
 UINT n=GetSystemDirectoryW(path,4096);if(!n||n>4000)return TRUE;wcscat(path,L"\\SystemSettings.DataModel.dll");if(!hashMatches(path,"f07bdc1334562d4ae3d5265e96cf44b8bfbde8388fd71e76cb698cc475703fbb"))return TRUE;
 HMODULE api=GetModuleHandleW(L"combase.dll");if(!api){preparation=CO_E_NOTINITIALIZED;return TRUE;}
 makeString=(void*)GetProcAddress(api,"WindowsCreateString");deleteString=(void*)GetProcAddress(api,"WindowsDeleteString");rawString=(void*)GetProcAddress(api,"WindowsGetStringRawBuffer");factoryFor=(void*)GetProcAddress(api,"RoGetActivationFactory");
 preparation=makeString&&deleteString&&rawString&&factoryFor?S_OK:E_NOINTERFACE;return TRUE;
}
static int scope(HS id){UINT32 n=0;PCWSTR s=rawString(id,&n);if(!s)return -1;for(int i=0;i<9;i++)if(n==wcslen(keys[i])&&!wmemcmp(s,keys[i],n))return i;return -1;}
static HRESULT queryName(void*self,int slot,PCWSTR text,void**value){HS key=NULL;HRESULT hr=makeString(text,(UINT32)wcslen(text),&key);if(SUCCEEDED(hr))hr=((QueryFn)(*(void***)self)[slot])(self,key,value);if(key)deleteString(key);return hr;}
/* New genuine manager per lookup: no apartment-crossing cache and no global map
   replacement. PRI must be loaded before this manager's first map access. */
static HRESULT resourceDescription(int index,HS*out){
 *out=NULL;HS cls=NULL;void*factory=NULL,*manager=NULL,*extension=NULL,*maps=NULL,*map=NULL,*subtree=NULL,*candidate=NULL;WCHAR name[160];HRESULT hr=makeString(L"Windows.ApplicationModel.Resources.Core.ResourceManager",55,&cls);if(FAILED(hr))goto done;
 hr=factoryFor(cls,&resourceStatics,&factory);if(FAILED(hr)||!factory)goto done;
 hr=((PtrFn)(*(void***)factory)[6])(factory,&manager);if(FAILED(hr)||!manager)goto done;
 hr=((QIFn)(*(void***)manager)[0])(manager,&resourceExt,&extension);if(FAILED(hr)||!extension)goto done;
 hr=((LoadPriFn)(*(void***)extension)[6])(extension,priPath);if(FAILED(hr))goto done;
 hr=((PtrFn)(*(void***)manager)[7])(manager,&maps);if(FAILED(hr)||!maps)goto done;
 hr=queryName(maps,6,L"Windows.UI.SettingsHandlers-nt",&map);if(FAILED(hr)||!map)goto done;
 hr=queryName(map,9,L"Resources",&subtree);if(FAILED(hr)||!subtree)goto done;
 if(swprintf(name,160,L"%lsDescription",keys[index])<0){hr=E_INVALIDARG;goto done;}
 hr=queryName(subtree,7,name,&candidate);if(FAILED(hr)||!candidate)goto done;
 hr=((PtrFn)(*(void***)candidate)[10])(candidate,out);
 done:if(SUCCEEDED(hr)&&(!candidate||!*out))hr=HRESULT_FROM_WIN32(ERROR_RESOURCE_NAME_NOT_FOUND);
 if(SUCCEEDED(hr)){UINT32 n=0;rawString(*out,&n);if(!n)hr=HRESULT_FROM_WIN32(ERROR_RESOURCE_NAME_NOT_FOUND);}
 if(FAILED(hr)&&*out){deleteString(*out);*out=NULL;}
 drop(&candidate);drop(&subtree);drop(&map);drop(&maps);drop(&extension);drop(&manager);drop(&factory);if(cls)deleteString(cls);return hr;
}
/* The export is also the real policy path used by the installed callsite. */
__declspec(dllexport) HRESULT WINAPI SettingsControlTextQuery(void*provided,HS*out){
 if(!out)return E_POINTER;*out=NULL;if(!provided)return E_POINTER;
 InitOnceExecuteOnce(&once,prepare,NULL,NULL);if(FAILED(preparation))return preparation;
 void*item=NULL;HS native=NULL,id=NULL;HRESULT hr=((QIFn)(*(void***)provided)[0])(provided,&itemIID,&item);if(FAILED(hr)||!item){if(SUCCEEDED(hr))hr=E_NOINTERFACE;goto done;}
 InterlockedIncrement(&SettingsControlTextNativeCalls);hr=((PtrFn)(*(void***)item)[11])(item,&native);if(FAILED(hr))goto done;
 UINT32 count=0;rawString(native,&count);
 if(hr!=S_OK||count){*out=native;native=NULL;goto done;}
 HRESULT idhr=((PtrFn)(*(void***)item)[6])(item,&id);
 if(FAILED(idhr)){hr=idhr;goto done;}
 int index=scope(id);if(index<0){*out=native;native=NULL;goto done;}
 hr=resourceDescription(index,out);if(SUCCEEDED(hr))InterlockedIncrement(&SettingsControlTextFallbackCalls);
 done:if(id)deleteString(id);if(native)deleteString(native);drop(&item);SettingsControlTextLastResult=hr;if(FAILED(hr))InterlockedIncrement(&SettingsControlTextFailures);return hr;
}
static HS WINAPI projection(void*item){HS result=NULL;HRESULT hr=SettingsControlTextQuery(item,&result);if(FAILED(hr))((void(WINAPI*)(HRESULT))((BYTE*)vmModule+0x100f8))(hr);return result;}
static BYTE* allocateNear(BYTE*target){SYSTEM_INFO si;GetSystemInfo(&si);uintptr_t center=(uintptr_t)target&~((uintptr_t)si.dwAllocationGranularity-1);
 for(uintptr_t distance=si.dwAllocationGranularity;distance<0x70000000;distance+=si.dwAllocationGranularity){uintptr_t addresses[2]={center+distance,center>distance?center-distance:0};for(int j=0;j<2;j++)if(addresses[j]>0x10000){BYTE*p=VirtualAlloc((void*)addresses[j],4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(p)return p;}}return NULL;}
/* Owned process bootstrap only. No concurrent VM consumers during install/restore. */
__declspec(dllexport) DWORD WINAPI SettingsControlTextInitialize(void*unused){
 if(hook)return memcmp(hook,installed,5)?HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH):installStatus;
 InitOnceExecuteOnce(&once,prepare,NULL,NULL);if(FAILED(preparation))return preparation;
 if(!vmModule)vmModule=LoadLibraryExW(vmPath,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if(!vmModule)return HRESULT_FROM_WIN32(GetLastError());
 if(!loadedAt(vmModule,vmPath))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 BYTE*context=(BYTE*)vmModule+0x398e4,*target=context+20;
 if(memcmp(context,callContext,sizeof(callContext)))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 HRESULT co=CoInitializeEx(NULL,COINIT_MULTITHREADED);if(FAILED(co)&&co!=RPC_E_CHANGED_MODE)return co;
 HRESULT check=S_OK;for(int i=0;i<9&&SUCCEEDED(check);i++){HS text=NULL;check=resourceDescription(i,&text);if(text)deleteString(text);}if(SUCCEEDED(co))CoUninitialize();if(FAILED(check))return check;
 BYTE*stub=allocateNear(target);if(!stub)return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
 BYTE code[14]={0xff,0x25,0,0,0,0};void*fn=projection;memcpy(code+6,&fn,8);memcpy(stub,code,sizeof(code));DWORD old=0,tmp=0;
 if(!VirtualProtect(stub,4096,PAGE_EXECUTE_READ,&old)||!FlushInstructionCache(GetCurrentProcess(),stub,14)){VirtualFree(stub,0,MEM_RELEASE);return E_FAIL;}
 intptr_t rel=(intptr_t)stub-(intptr_t)(target+5);if(rel<INT32_MIN||rel>INT32_MAX){VirtualFree(stub,0,MEM_RELEASE);return E_FAIL;}
 installed[0]=0xe8;INT32 disp=(INT32)rel;memcpy(installed+1,&disp,4);
 HMODULE pin=NULL;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(PCWSTR)projection,&pin)){VirtualFree(stub,0,MEM_RELEASE);return HRESULT_FROM_WIN32(GetLastError());}
 if(!VirtualProtect(target,5,PAGE_EXECUTE_READWRITE,&old)){VirtualFree(stub,0,MEM_RELEASE);return HRESULT_FROM_WIN32(GetLastError());}
 memcpy(target,installed,5);BOOL protect=VirtualProtect(target,5,old,&tmp);BOOL flush=FlushInstructionCache(GetCurrentProcess(),target,5);hook=target;trampoline=stub;InterlockedExchange(&SettingsControlTextInstalled,1);
 if(!protect||!flush||memcmp(target,installed,5)){installStatus=E_FAIL;return installStatus;}
 installStatus=S_OK;
 OutputDebugStringW(L"SettingsControlTextCompat installed one guarded oldVM Description callsite; native first, exact9 genuine old NT PRI descriptions only.");return S_OK;
}
__declspec(dllexport) DWORD WINAPI SettingsControlTextRestore(void*unused){
 if(!hook)return S_OK;if(memcmp(hook,installed,5))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 DWORD old=0,tmp=0;if(!VirtualProtect(hook,5,PAGE_EXECUTE_READWRITE,&old))return HRESULT_FROM_WIN32(GetLastError());memcpy(hook,callContext+20,5);BOOL protect=VirtualProtect(hook,5,old,&tmp),flush=FlushInstructionCache(GetCurrentProcess(),hook,5);if(!protect||!flush||memcmp(hook,callContext+20,5))return E_FAIL;
 hook=NULL;installStatus=E_PENDING;InterlockedExchange(&SettingsControlTextInstalled,0);if(trampoline){VirtualFree(trampoline,0,MEM_RELEASE);trampoline=NULL;}return S_OK;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,void*reserved){if(reason==DLL_PROCESS_ATTACH){selfModule=module;DisableThreadLibraryCalls(module);}return TRUE;}
