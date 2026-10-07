#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dwmapi.h>
#include <psapi.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include "../SettingsContentCompat/HashCheck.h"
#include "Guard.h"
typedef HRESULT(WINAPI*SET)(HWND,DWORD,LPCVOID,DWORD);
typedef struct{HWND window;DWORD thread;int before;ULONG_PTR token;} RECORD;
typedef struct{HMODULE module;void**slot;DWORD protection;BOOL owned,protectionPending;} HOOK;
static RECORD records[1024];static DWORD count;static SRWLOCK lock=SRWLOCK_INIT;
static HOOK hooks[3];static SET original;static WCHAR property[160];static BOOL pending;
__declspec(dllexport) volatile LONG MenuSquareInstalled;
__declspec(dllexport) volatile LONG MenuSquareHits[3],MenuSquareFailures,MenuSquareDelayResolved[3],MenuSquareDelayHRESULT[3];
__declspec(dllexport) ULONG_PTR MenuSquareSlots[3],MenuSquareOriginal,MenuSquareReplacements[3];
#define installed MenuSquareInstalled
static BOOL physical(HMODULE m,PCWSTR dos){WCHAR actual[32768],device[32768],expected[32768],drive[3]={dos[0],L':',0};if(!GetMappedFileNameW(GetCurrentProcess(),m,actual,32768)||!QueryDosDeviceW(drive,device,32768))return FALSE;swprintf(expected,32768,L"%ls%ls",device,dos+2);return !_wcsicmp(actual,expected);}
static BOOL ownMenu(HWND w){DWORD pid=0;GetWindowThreadProcessId(w,&pid);WCHAR name[80];return pid==GetCurrentProcessId()&&GetClassNameW(w,name,80)&&!wcscmp(name,L"#32768");}
static HRESULT squareSet(UINT index,void*caller,HWND w,DWORD attr,LPCVOID value,DWORD size){
 SET next=original;
 if(!InterlockedCompareExchange(&installed,0,0)||attr!=33||size!=4||!value||*(const int*)value!=3||caller!=(BYTE*)hooks[index].module+specs[index].caller||!ownMenu(w))return next(w,attr,value,size);
 AcquireSRWLockExclusive(&lock);if(!installed){ReleaseSRWLockExclusive(&lock);return next(w,attr,value,size);}
 for(DWORD i=0;i<count;){RECORD*r=&records[i];if(!IsWindow(r->window)||GetPropW(r->window,property)!=(HANDLE)r->token)records[i]=records[--count];else i++;}
 BOOL known=FALSE;for(DWORD i=0;i<count;i++)if(records[i].window==w&&GetPropW(w,property)==(HANDLE)records[i].token){known=TRUE;break;}
 int before=0;HRESULT get=DwmGetWindowAttribute(w,33,&before,4);if(FAILED(get)||(!known&&count==1024)){ReleaseSRWLockExclusive(&lock);InterlockedIncrement(&MenuSquareFailures);return next(w,attr,value,size);}
 if(!known){ULONG_PTR token=(ULONG_PTR)w^(ULONG_PTR)GetTickCount64()^(ULONG_PTR)&records;if(!token)token=1;if(!SetPropW(w,property,(HANDLE)token)){ReleaseSRWLockExclusive(&lock);InterlockedIncrement(&MenuSquareFailures);return next(w,attr,value,size);}records[count++]=(RECORD){w,GetWindowThreadProcessId(w,NULL),before,token};}
 int square=1;HRESULT result=next(w,33,&square,4);int after=0;HRESULT read=DwmGetWindowAttribute(w,33,&after,4);if(SUCCEEDED(result)&&SUCCEEDED(read)&&after==1)InterlockedIncrement(&MenuSquareHits[index]);else InterlockedIncrement(&MenuSquareFailures);ReleaseSRWLockExclusive(&lock);return result;
}
static HRESULT WINAPI uxSet(HWND w,DWORD a,LPCVOID p,DWORD n){return squareSet(0,__builtin_return_address(0),w,a,p,n);}
static HRESULT WINAPI pcsSet(HWND w,DWORD a,LPCVOID p,DWORD n){return squareSet(1,__builtin_return_address(0),w,a,p,n);}
static HRESULT WINAPI shellSet(HWND w,DWORD a,LPCVOID p,DWORD n){return squareSet(2,__builtin_return_address(0),w,a,p,n);}
static void*replacement[3]={(void*)uxSet,(void*)pcsSet,(void*)shellSet};
static BOOL bytesOkay(HMODULE module,const SPEC*s){for(UINT i=0;i<s->guardCount;i++){const GUARD*g=&s->guards[i];if(memcmp((BYTE*)module+g->rva,g->bytes,g->length))return FALSE;}return TRUE;}
static DWORD restoreSlots(void){DWORD errors=0;for(UINT i=0;i<3;i++){HOOK*h=&hooks[i];if(!h->owned&&!h->protectionPending)continue;if(*h->slot!=replacement[i]&&*h->slot!=(void*)original){errors++;continue;}DWORD old,ignored;if(!VirtualProtect(h->slot,8,PAGE_READWRITE,&old)){errors++;continue;}void*before=InterlockedCompareExchangePointer(h->slot,(void*)original,replacement[i]);BOOL okay=VirtualProtect(h->slot,8,h->protection,&ignored);h->protectionPending=!okay;if(before==replacement[i]||before==(void*)original)h->owned=FALSE;else errors++;if(!okay)errors++;}return errors;}
static DWORD initialize(BOOL fixture){
 AcquireSRWLockExclusive(&lock);if(installed||pending){DWORD r=pending?ERROR_BUSY:0;if(installed)for(UINT i=0;i<3;i++)if(!hooks[i].slot||*hooks[i].slot!=replacement[i])r=ERROR_BUSY;ReleaseSRWLockExclusive(&lock);return r;}
 WCHAR exe[32768];GetModuleFileNameW(NULL,exe,32768);if(!((!_wcsicmp(exe,fixture?FIXTURE_PATH:EXPLORER_PATH)&&hashMatches(exe,fixture?FIXTURE_SHA:EXPLORER_SHA))||(fixture&&!_wcsicmp(exe,ALT_FIXTURE_PATH)&&hashMatches(exe,ALT_FIXTURE_SHA)))){ReleaseSRWLockExclusive(&lock);return ERROR_ACCESS_DENIED;}
 HMODULE dwm=LoadLibraryW(L"C:\\Windows\\System32\\dwmapi.dll");if(!dwm||!physical(dwm,DWM_PATH)||!hashMatches(DWM_PATH,DWM_SHA)){ReleaseSRWLockExclusive(&lock);return ERROR_REVISION_MISMATCH;}
 original=(SET)GetProcAddress(dwm,"DwmSetWindowAttribute");if((BYTE*)original!=(BYTE*)dwm+DWM_EXPORT_RVA){ReleaseSRWLockExclusive(&lock);return ERROR_REVISION_MISMATCH;}
 HMODULE pinned;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN|GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(PCWSTR)original,&pinned)||!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN|GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(PCWSTR)uxSet,&pinned)){ReleaseSRWLockExclusive(&lock);return ERROR_ACCESS_DENIED;}
 for(UINT i=0;i<3;i++){
  const SPEC*s=&specs[i];HOOK*h=&hooks[i];HMODULE module=GetModuleHandleW(s->baseName);if(!module&&i==0)module=LoadLibraryW(s->path);
  if(!module||!physical(module,s->path)||!hashMatches(s->path,s->sha)||!bytesOkay(module,s)){ReleaseSRWLockExclusive(&lock);return ERROR_REVISION_MISMATCH;}
  if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN|GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(PCWSTR)module,&pinned)){ReleaseSRWLockExclusive(&lock);return ERROR_ACCESS_DENIED;}
  h->module=module;h->slot=(void**)((BYTE*)module+s->iat);
  if(*h->slot==(BYTE*)module+s->thunk){int one=1;HRESULT result=((SET)*h->slot)(NULL,33,&one,4);InterlockedExchange(&MenuSquareDelayHRESULT[i],result);InterlockedExchange(&MenuSquareDelayResolved[i],*h->slot==(void*)original);}
  if(*h->slot!=(void*)original){ReleaseSRWLockExclusive(&lock);return ERROR_BUSY;}
 }
 swprintf(property,160,L"Codex.MenuSquareV2.%lu.%p",GetCurrentProcessId(),uxSet);DWORD error=0;
 for(UINT i=0;i<3;i++){HOOK*h=&hooks[i];DWORD old,ignored;if(!VirtualProtect(h->slot,8,PAGE_READWRITE,&old)){error=ERROR_WRITE_FAULT;break;}h->protection=old;h->protectionPending=TRUE;void*before=InterlockedCompareExchangePointer(h->slot,replacement[i],(void*)original);h->owned=before==(void*)original;BOOL okay=VirtualProtect(h->slot,8,old,&ignored);h->protectionPending=!okay;if(!h->owned||!okay){error=h->owned?ERROR_WRITE_FAULT:ERROR_BUSY;break;}}
 if(error){pending=restoreSlots()!=0;ReleaseSRWLockExclusive(&lock);return error;}
 for(UINT i=0;i<3;i++){MenuSquareSlots[i]=(ULONG_PTR)hooks[i].slot;MenuSquareReplacements[i]=(ULONG_PTR)replacement[i];}MenuSquareOriginal=(ULONG_PTR)original;InterlockedExchange(&installed,TRUE);ReleaseSRWLockExclusive(&lock);return 0;
}
__declspec(dllexport) DWORD WINAPI MenuSquareInitialize(void*unused){(void)unused;return initialize(FALSE);}
__declspec(dllexport) DWORD WINAPI MenuSquareFixtureInitialize(void*unused){(void)unused;return initialize(TRUE);}
__declspec(dllexport) DWORD WINAPI MenuSquareRestore(void*unused){(void)unused;AcquireSRWLockExclusive(&lock);if(!installed&&!pending){ReleaseSRWLockExclusive(&lock);return 0;}InterlockedExchange(&installed,FALSE);DWORD errors=restoreSlots();
 for(DWORD i=0;i<count;){RECORD*r=&records[i];BOOL keep=FALSE;if(ownMenu(r->window)&&GetPropW(r->window,property)==(HANDLE)r->token){int current;HRESULT get=DwmGetWindowAttribute(r->window,33,&current,4);if(FAILED(get)){errors++;keep=TRUE;}else if(current==1){HRESULT set=original(r->window,33,&r->before,4);int after;if(FAILED(set)||FAILED(DwmGetWindowAttribute(r->window,33,&after,4))||after!=r->before){errors++;keep=TRUE;}}if(!keep)RemovePropW(r->window,property);}if(keep)i++;else records[i]=records[--count];}
 pending=errors!=0;ReleaseSRWLockExclusive(&lock);return errors?ERROR_WRITE_FAULT:0;
}
BOOL WINAPI DllMain(HINSTANCE m,DWORD reason,void*reserved){(void)reserved;if(reason==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(m);return TRUE;}
