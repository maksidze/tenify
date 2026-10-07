#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <shellapi.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include "../SettingsContentCompat/HashCheck.h"
#include "Routes.h"
static HMODULE self;
typedef struct {void **slot;void *before,*after;} PATCH;
static PATCH patches[8192];static DWORD patchCount;static BOOL installed,restorePending;static volatile BOOL active;
static SRWLOCK lifecycleLock=SRWLOCK_INIT;static SRWLOCK patchLock=SRWLOCK_INIT;static HMODULE holds[2048];static DWORD holdCount;
typedef struct {HRSRC resource;HMODULE module;} RESOURCE;
static RESOURCE refs[8192];static DWORD refCount;static SRWLOCK lock=SRWLOCK_INIT;
static HMODULE data[ROUTE_COUNT];
static volatile LONG routeHits;
static int pathIndex(PCWSTR path){WCHAR expanded[32768],full[32768];if(!path||!ExpandEnvironmentStringsW(path,expanded,32768))return -1;BOOL bare=!wcschr(expanded,L'\\')&&!wcschr(expanded,L'/')&&!wcschr(expanded,L':');if(bare){DWORD n=SearchPathW(NULL,expanded,NULL,32768,full,NULL);if(!n||n>=32768)return -1;}else{DWORD n=GetFullPathNameW(expanded,32768,full,NULL);if(!n||n>=32768)return -1;}for(int i=0;i<ROUTE_COUNT;i++)if(!_wcsicmp(full,routes[i].host))return i;return -1;}
static HMODULE routeModule(HMODULE module){WCHAR path[32768];if(!active||!module)return module;if(!GetModuleFileNameW(module,path,32768))return module;int i=pathIndex(path);return i<0?module:data[i];}
static PCWSTR routePath(PCWSTR path){if(!active)return path;int i=pathIndex(path);if(i>=0)InterlockedIncrement(&routeHits);return i<0?path:routes[i].privatePath;}
static BOOL iconType(PCWSTR type){return (ULONG_PTR)type==3||(ULONG_PTR)type==14;}
static HRSRC remember(HRSRC resource,HMODULE module){if(!resource)return NULL;AcquireSRWLockExclusive(&lock);for(DWORD i=0;i<refCount;i++)if(refs[i].resource==resource){ReleaseSRWLockExclusive(&lock);return resource;}if(refCount==8192){ReleaseSRWLockExclusive(&lock);SetLastError(ERROR_NOT_ENOUGH_MEMORY);return NULL;}refs[refCount++]=(RESOURCE){resource,module};ReleaseSRWLockExclusive(&lock);return resource;}
static HMODULE resourceModule(HMODULE original,HRSRC resource){HMODULE m=original;AcquireSRWLockShared(&lock);for(DWORD i=0;i<refCount;i++)if(refs[i].resource==resource){m=refs[i].module;break;}ReleaseSRWLockShared(&lock);return m;}
static HICON WINAPI hookLoadIconW(HINSTANCE m,PCWSTR name){return LoadIconW((HINSTANCE)routeModule(m),name);}
static HICON WINAPI hookLoadIconA(HINSTANCE m,PCSTR name){return LoadIconA((HINSTANCE)routeModule(m),name);}
static HANDLE WINAPI hookLoadImageW(HINSTANCE m,PCWSTR name,UINT type,int x,int y,UINT flags){return LoadImageW(type==IMAGE_ICON&&!(flags&LR_LOADFROMFILE)?(HINSTANCE)routeModule(m):m,name,type,x,y,flags);}
static HANDLE WINAPI hookLoadImageA(HINSTANCE m,PCSTR name,UINT type,int x,int y,UINT flags){return LoadImageA(type==IMAGE_ICON&&!(flags&LR_LOADFROMFILE)?(HINSTANCE)routeModule(m):m,name,type,x,y,flags);}
static HRSRC WINAPI hookFindResourceW(HMODULE m,PCWSTR name,PCWSTR type){HMODULE r=iconType(type)?routeModule(m):m;HRSRC v=FindResourceW(r,name,type);return r!=m?remember(v,r):v;}
static HRSRC WINAPI hookFindResourceA(HMODULE m,PCSTR name,PCSTR type){HMODULE r=iconType((PCWSTR)type)?routeModule(m):m;HRSRC v=FindResourceA(r,name,type);return r!=m?remember(v,r):v;}
static HRSRC WINAPI hookFindResourceExW(HMODULE m,PCWSTR type,PCWSTR name,WORD lang){HMODULE r=iconType(type)?routeModule(m):m;HRSRC v=FindResourceExW(r,type,name,lang);return r!=m?remember(v,r):v;}
static HRSRC WINAPI hookFindResourceExA(HMODULE m,PCSTR type,PCSTR name,WORD lang){HMODULE r=iconType((PCWSTR)type)?routeModule(m):m;HRSRC v=FindResourceExA(r,type,name,lang);return r!=m?remember(v,r):v;}
static HGLOBAL WINAPI hookLoadResource(HMODULE m,HRSRC r){return LoadResource(resourceModule(m,r),r);}
static DWORD WINAPI hookSizeofResource(HMODULE m,HRSRC r){return SizeofResource(resourceModule(m,r),r);}
static UINT WINAPI hookExtractIconExW(PCWSTR file,int index,HICON*large,HICON*small,UINT count){return ExtractIconExW(routePath(file),index,large,small,count);}
static HICON WINAPI hookExtractIconW(HINSTANCE m,PCWSTR file,UINT index){return ExtractIconW(m,routePath(file),index);}
static UINT WINAPI hookPrivateExtractIconsW(PCWSTR file,int index,int x,int y,HICON*out,UINT*ids,UINT count,UINT flags){return PrivateExtractIconsW(routePath(file),index,x,y,out,ids,count,flags);}
static BOOL ansiPath(PCSTR p,WCHAR*out){return p&&MultiByteToWideChar(CP_ACP,0,p,-1,out,32768)>0;}
static UINT WINAPI hookExtractIconExA(PCSTR f,int i,HICON*l,HICON*s,UINT n){WCHAR w[32768];return ansiPath(f,w)?hookExtractIconExW(w,i,l,s,n):ExtractIconExA(f,i,l,s,n);}
static HICON WINAPI hookExtractIconA(HINSTANCE m,PCSTR f,UINT i){WCHAR w[32768];return ansiPath(f,w)?hookExtractIconW(m,w,i):ExtractIconA(m,f,i);}
typedef struct{PCSTR name;void *original,*hook;} HOOK;
#define H(module,name) {#name,(void*)GetProcAddress(GetModuleHandleW(module),#name),(void*)hook##name}
static HOOK hooks[32];static DWORD hookCount;
static BOOL patchModule(HMODULE module);
static FARPROC WINAPI hookGetProcAddress(HMODULE module,PCSTR name){FARPROC p=GetProcAddress(module,name);if(!active)return p;if((ULONG_PTR)name>65535)for(DWORD i=0;i<hookCount;i++)if(!strcmp(name,hooks[i].name)&&(void*)p==hooks[i].original)return (FARPROC)hooks[i].hook;return p;}
static HMODULE WINAPI hookLoadLibraryExW(PCWSTR path,HANDLE file,DWORD flags){/* IMAGE_RESOURCE alone is not an established data-only request. */BOOL resource=(flags&(LOAD_LIBRARY_AS_DATAFILE|LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE))!=0;HMODULE m=LoadLibraryExW(resource?routePath(path):path,file,flags);if(m&&!resource&&!(flags&LOAD_LIBRARY_AS_IMAGE_RESOURCE))patchModule(m);return m;}
static HMODULE WINAPI hookLoadLibraryW(PCWSTR path){HMODULE m=LoadLibraryW(path);if(m)patchModule(m);return m;}
static BOOL patchModuleLocked(HMODULE module){if(module==self)return TRUE;BYTE*b=(BYTE*)module;IMAGE_DOS_HEADER*d=(void*)b;if(d->e_magic!=IMAGE_DOS_SIGNATURE)return TRUE;IMAGE_NT_HEADERS*n=(void*)(b+d->e_lfanew);if(n->Signature!=IMAGE_NT_SIGNATURE)return TRUE;DWORD rva=n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;if(!rva)return TRUE;IMAGE_IMPORT_DESCRIPTOR*desc=(void*)(b+rva);for(;desc->Name;desc++){if(!desc->OriginalFirstThunk)continue;IMAGE_THUNK_DATA*names=(void*)(b+desc->OriginalFirstThunk),*iat=(void*)(b+desc->FirstThunk);for(;names->u1.AddressOfData;names++,iat++){if(IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal))continue;PCSTR name=((IMAGE_IMPORT_BY_NAME*)(b+names->u1.AddressOfData))->Name;for(DWORD h=0;h<hookCount;h++){if(strcmp(name,hooks[h].name)||!hooks[h].original)continue;void**slot=(void**)&iat->u1.Function;if(*slot==hooks[h].hook)break;if(*slot!=hooks[h].original)break;if(patchCount==8192)return FALSE;BOOL held=FALSE;for(DWORD k=0;k<holdCount;k++)if(holds[k]==module){held=TRUE;break;}if(!held){if(holdCount==2048)return FALSE;HMODULE hold;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(PCWSTR)module,&hold)||hold!=module)return FALSE;holds[holdCount++]=hold;}DWORD old;if(!VirtualProtect(slot,sizeof(void*),PAGE_READWRITE,&old))return FALSE;void*prior=InterlockedCompareExchangePointer(slot,hooks[h].hook,hooks[h].original);DWORD discard;VirtualProtect(slot,sizeof(void*),old,&discard);if(prior==hooks[h].original)patches[patchCount++]=(PATCH){slot,prior,hooks[h].hook};break;}}}return TRUE;}
static BOOL patchModule(HMODULE module){AcquireSRWLockExclusive(&patchLock);BOOL ok=TRUE;HMODULE temporary=NULL;if(active&&GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(PCWSTR)module,&temporary)){if(temporary==module)ok=patchModuleLocked(module);else ok=FALSE;}ReleaseSRWLockExclusive(&patchLock);if(temporary)FreeLibrary(temporary);return ok;}
__declspec(dllexport) DWORD WINAPI RefreshIconRoutes(void*unused){(void)unused;HMODULE modules[2048];DWORD needed;if(!EnumProcessModules(GetCurrentProcess(),modules,sizeof(modules),&needed)||needed>sizeof(modules))return ERROR_INSUFFICIENT_BUFFER;for(DWORD i=0;i<needed/sizeof(HMODULE);i++)if(!patchModule(modules[i]))return ERROR_WRITE_FAULT;return ERROR_SUCCESS;}
static DWORD restoreLocked(void*unused){(void)unused;AcquireSRWLockExclusive(&patchLock);active=FALSE;DWORD failures=0,foreign=0;for(DWORD i=patchCount;i>0;i--){PATCH*p=&patches[i-1];void*current=*p->slot;if(current==p->before)continue;if(current!=p->after){foreign++;continue;}DWORD old;if(!VirtualProtect(p->slot,8,PAGE_READWRITE,&old)){failures++;continue;}void*observed=InterlockedCompareExchangePointer(p->slot,p->before,p->after);if(observed!=p->after&&observed!=p->before)foreign++;DWORD ignored;VirtualProtect(p->slot,8,old,&ignored);}if(failures||foreign){restorePending=TRUE;ReleaseSRWLockExclusive(&patchLock);return failures?ERROR_WRITE_FAULT:ERROR_BUSY;}patchCount=0;installed=FALSE;restorePending=FALSE;/* All consumer slots are restored before releasing module references. */HMODULE release[2048];DWORD n=holdCount;memcpy(release,holds,n*sizeof(HMODULE));holdCount=0;ReleaseSRWLockExclusive(&patchLock);for(DWORD i=0;i<n;i++)FreeLibrary(release[i]);/* Retain datafiles for outstanding caller-owned HRSRC/HICON. */return ERROR_SUCCESS;}
static DWORD initialize(BOOL fixture){if(installed)return restorePending?ERROR_BUSY:ERROR_SUCCESS;WCHAR exe[32768];GetModuleFileNameW(NULL,exe,32768);if(_wcsicmp(exe,fixture?FIXTURE_PATH:EXPLORER_PATH)||!hashMatches(exe,fixture?FIXTURE_SHA:EXPLORER_SHA))return ERROR_ACCESS_DENIED;for(int i=0;i<ROUTE_COUNT;i++){if(!hashMatches(routes[i].host,routes[i].hostSha)||!hashMatches(routes[i].privatePath,routes[i].privateSha))return ERROR_REVISION_MISMATCH;if(!data[i])data[i]=LoadLibraryExW(routes[i].privatePath,NULL,LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE|LOAD_LIBRARY_AS_IMAGE_RESOURCE);if(!data[i])return GetLastError();}
 HOOK list[]={H(L"user32.dll",LoadIconW),H(L"user32.dll",LoadIconA),H(L"user32.dll",LoadImageW),H(L"user32.dll",LoadImageA),H(L"kernel32.dll",FindResourceW),H(L"kernel32.dll",FindResourceA),H(L"kernel32.dll",FindResourceExW),H(L"kernel32.dll",FindResourceExA),H(L"kernel32.dll",LoadResource),H(L"kernel32.dll",SizeofResource),H(L"shell32.dll",ExtractIconW),H(L"shell32.dll",ExtractIconA),H(L"shell32.dll",ExtractIconExW),H(L"shell32.dll",ExtractIconExA),H(L"user32.dll",PrivateExtractIconsW),H(L"kernel32.dll",LoadLibraryW),H(L"kernel32.dll",LoadLibraryExW),H(L"kernel32.dll",GetProcAddress)};active=TRUE;hookCount=sizeof(list)/sizeof(list[0]);memcpy(hooks,list,sizeof(list));HMODULE modules[2048];DWORD needed;if(!EnumProcessModules(GetCurrentProcess(),modules,sizeof(modules),&needed)||needed>sizeof(modules))return ERROR_INSUFFICIENT_BUFFER;for(DWORD i=0;i<needed/sizeof(HMODULE);i++)if(!patchModule(modules[i])){restoreLocked(NULL);return ERROR_WRITE_FAULT;}installed=TRUE;return ERROR_SUCCESS;}
__declspec(dllexport) DWORD WINAPI InitializeIconRoutes(void*unused){(void)unused;AcquireSRWLockExclusive(&lifecycleLock);DWORD r=initialize(FALSE);ReleaseSRWLockExclusive(&lifecycleLock);return r;}
__declspec(dllexport) DWORD WINAPI InitializeIconRoutesFixture(void*unused){(void)unused;AcquireSRWLockExclusive(&lifecycleLock);DWORD r=initialize(TRUE);ReleaseSRWLockExclusive(&lifecycleLock);return r;}
__declspec(dllexport) DWORD WINAPI RestoreIconRoutes(void*unused){AcquireSRWLockExclusive(&lifecycleLock);DWORD r=restoreLocked(unused);ReleaseSRWLockExclusive(&lifecycleLock);return r;}
__declspec(dllexport) DWORD WINAPI GetIconRoutePatchCount(void*unused){(void)unused;AcquireSRWLockShared(&patchLock);DWORD n=patchCount;ReleaseSRWLockShared(&patchLock);return n;}
__declspec(dllexport) DWORD WINAPI GetIconRouteHits(void*unused){(void)unused;return (DWORD)routeHits;}
BOOL WINAPI DllMain(HINSTANCE m,DWORD reason,void*unused){(void)unused;if(reason==DLL_PROCESS_ATTACH){self=m;DisableThreadLibraryCalls(m);}return TRUE;}
