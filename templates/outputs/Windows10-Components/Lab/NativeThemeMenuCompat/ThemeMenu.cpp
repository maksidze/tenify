#include <windows.h>
#include <uxtheme.h>
#include <psapi.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <initializer_list>
#include "../Theme10BrowserProbe/HashCheck.hpp"
#include "Pins.h"
struct STATE{DWORD size,version,result,active,mappedPlain,mappedPcs,mappedShell,passed,rejected,generationRejected,failures,restores,codeSites,iatSlots,quarantined,reserved;ULONGLONG oldFile,app,ux,pcs,shell,callTable,iatTable,processDpiBefore,processDpiAfter,threadDpiBefore,threadDpiAfter,oldReference;};
static_assert(sizeof(STATE)==160,"readback ABI");
struct CallRow{DWORD module,rva,length,api;ULONGLONG address,thunk;BYTE original[8],replacement[8];DWORD protection,published;};
static_assert(sizeof(CallRow)==56,"call readback ABI");
extern "C" __declspec(dllexport) STATE ThemeMenuState={sizeof(STATE),1};
static CallRow calls[17];static SRWLOCK gate=SRWLOCK_INIT;static bool installed,terminalFailure;static HMODULE modules[3];static BYTE*islands[3];static void*app,*oldFile;static HTHEME retained;
using FromData=HRESULT(WINAPI*)(HTHEME,void**);using GetClass=HRESULT(WINAPI*)(HTHEME,PWSTR,int);static FromData fromData;static GetClass getClass;
static bool mapped(HMODULE m,PCWSTR expected){WCHAR actual[32768],disk[32768],want[32768],drive[]={expected[0],L':',0};if(!K32GetMappedFileNameW(GetCurrentProcess(),m,actual,32768)||!QueryDosDeviceW(drive,disk,32768)||wcslen(disk)+wcslen(expected+2)>=32768)return false;wcscpy(want,disk);wcscat(want,expected+2);return !_wcsicmp(actual,want);}
static bool sameGeneration(){return app&&*(void**)((BYTE*)app+8)==oldFile;}
static LONG*counter(DWORD module){return (LONG*)(module==0?&ThemeMenuState.mappedPlain:module==1?&ThemeMenuState.mappedPcs:&ThemeMenuState.mappedShell);}
// Return part unchanged, old part14, or -1 (explicit stale-generation failure).
// No retained menu-handle table: native GetThemeClass validates the caller's live handle.
static int mapPart(HTHEME h,int part,int state,void*caller){
 if(part!=27||state<0||state>4){InterlockedIncrement((LONG*)&ThemeMenuState.passed);return part;}
 DWORD module=3;for(auto&r:calls)if(r.published&&(BYTE*)caller==(BYTE*)r.address+5){module=r.module;break;}
 if(module==3){InterlockedIncrement((LONG*)&ThemeMenuState.rejected);return part;}
 if(!sameGeneration()){InterlockedIncrement((LONG*)&ThemeMenuState.generationRejected);return -1;}
 void*file=nullptr;if(FAILED(fromData(h,&file))||file!=oldFile){InterlockedIncrement((LONG*)&ThemeMenuState.rejected);return part;}
 struct{WCHAR before;WCHAR name[128];WCHAR after;}c={};c.before=L'X';c.after=L'Y';HRESULT hr=getClass(h,c.name,128);
 if(c.before!=L'X'||c.after!=L'Y'){InterlockedIncrement((LONG*)&ThemeMenuState.failures);return -1;}
 if(FAILED(hr)||_wcsicmp(c.name,L"Menu")){InterlockedIncrement((LONG*)&ThemeMenuState.rejected);return part;}
 InterlockedIncrement(counter(module));return 14;
}
using IntFn=HRESULT(WINAPI*)(HTHEME,int,int,int,int*);using MargFn=HRESULT(WINAPI*)(HTHEME,HDC,int,int,int,RECT*,MARGINS*);using TransFn=BOOL(WINAPI*)(HTHEME,int,int);using BgFn=HRESULT(WINAPI*)(HTHEME,HDC,int,int,const RECT*,const RECT*);using TextFn=HRESULT(WINAPI*)(HTHEME,HDC,int,int,PCWSTR,int,DWORD,DWORD,const RECT*);using ExtentFn=HRESULT(WINAPI*)(HTHEME,HDC,int,int,PCWSTR,int,DWORD,const RECT*,RECT*);using ColorFn=HRESULT(WINAPI*)(HTHEME,int,int,int,COLORREF*);using TextExFn=HRESULT(WINAPI*)(HTHEME,HDC,int,int,PCWSTR,int,DWORD,RECT*,const DTTOPTS*);
static void*real[8];
struct ReadLock{ReadLock(){AcquireSRWLockShared(&gate);}~ReadLock(){ReleaseSRWLockShared(&gate);}};
#define MAP() ReadLock lock;int q=installed?mapPart(h,p,s,__builtin_return_address(0)):p;if(q<0)return E_HANDLE
static HRESULT WINAPI hookInt(HTHEME h,int p,int s,int prop,int*out){MAP();return ((IntFn)real[0])(h,q,s,prop,out);}
static HRESULT WINAPI hookMargins(HTHEME h,HDC dc,int p,int s,int prop,RECT*r,MARGINS*out){MAP();return ((MargFn)real[1])(h,dc,q,s,prop,r,out);}
static BOOL WINAPI hookTransparent(HTHEME h,int p,int s){ReadLock lock;int q=installed?mapPart(h,p,s,__builtin_return_address(0)):p;if(q<0){SetLastError(ERROR_INVALID_HANDLE);return FALSE;}return ((TransFn)real[2])(h,q,s);}
static HRESULT WINAPI hookBackground(HTHEME h,HDC dc,int p,int s,const RECT*r,const RECT*c){MAP();return ((BgFn)real[3])(h,dc,q,s,r,c);}
static HRESULT WINAPI hookText(HTHEME h,HDC dc,int p,int s,PCWSTR text,int count,DWORD flags,DWORD flags2,const RECT*r){MAP();return ((TextFn)real[4])(h,dc,q,s,text,count,flags,flags2,r);}
static HRESULT WINAPI hookExtent(HTHEME h,HDC dc,int p,int s,PCWSTR text,int count,DWORD flags,const RECT*r,RECT*out){MAP();return ((ExtentFn)real[5])(h,dc,q,s,text,count,flags,r,out);}
static HRESULT WINAPI hookColor(HTHEME h,int p,int s,int prop,COLORREF*out){MAP();return ((ColorFn)real[6])(h,q,s,prop,out);}
static HRESULT WINAPI hookTextEx(HTHEME h,HDC dc,int p,int s,PCWSTR text,int count,DWORD flags,RECT*r,const DTTOPTS*o){MAP();return ((TextExFn)real[7])(h,dc,q,s,text,count,flags,r,o);}
#undef MAP
static void*wrappers[]={(void*)hookInt,(void*)hookMargins,(void*)hookTransparent,(void*)hookBackground,(void*)hookText,(void*)hookExtent,(void*)hookColor,(void*)hookTextEx};
static BYTE*nearPage(BYTE*base){uintptr_t center=(uintptr_t)base&~uintptr_t(0xffff);for(uintptr_t delta=0x10000;delta<0x70000000;delta+=0x10000){for(int sign:{1,-1}){uintptr_t where=sign>0?center+delta:center-delta;MEMORY_BASIC_INFORMATION m={};if(!VirtualQuery((void*)where,&m,sizeof(m))||m.State!=MEM_FREE)continue;auto p=(BYTE*)VirtualAlloc((void*)where,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(p)return p;}}return nullptr;}
static bool currentPath(){WCHAR p[32768],c[100],s[100];return SUCCEEDED(GetCurrentThemeName(p,32768,c,100,s,100))&&!_wcsicmp(p,OLD_AERO_PATH)&&!wcscmp(c,L"NormalColor")&&!wcscmp(s,L"NormalSize");}
static DWORD restoreLocked(){
 if(installed&&!sameGeneration())return ERROR_BUSY;
 for(auto&r:calls)if(r.published&&memcmp((void*)r.address,r.replacement,r.length))return ERROR_BUSY;
 DWORD result=0;for(int i=16;i>=0;i--){auto&r=calls[i];if(!r.published)continue;DWORD old,ignore;if(!VirtualProtect((void*)r.address,r.length,PAGE_EXECUTE_READWRITE,&old)){result=GetLastError();break;}memcpy((void*)r.address,r.original,r.length);BOOL flushed=FlushInstructionCache(GetCurrentProcess(),(void*)r.address,r.length),protectedAgain=VirtualProtect((void*)r.address,r.length,r.protection,&ignore);if(!flushed||!protectedAgain){result=ERROR_WRITE_FAULT;break;}r.published=0;}
 if(result){terminalFailure=true;ThemeMenuState.quarantined=1;return result;}
 installed=false;ThemeMenuState.active=0;if(retained){CloseThemeData(retained);retained=nullptr;ThemeMenuState.oldReference=0;}ThemeMenuState.restores++;
 // Keep code islands/module pinned for saved callback pointers. Only disposable-host teardown releases them.
 return 0;
}
static DWORD initialize(bool fixture){AcquireSRWLockExclusive(&gate);DWORD result=0;
 if(terminalFailure){result=ERROR_INVALID_STATE;goto end;}
 if(installed){if(!sameGeneration())result=ERROR_BUSY;for(auto&r:calls)if(memcmp((void*)r.address,r.replacement,r.length))result=ERROR_BUSY;goto end;}
 {WCHAR p[32768];if(!GetModuleFileNameW(nullptr,p,32768)||!mapped(GetModuleHandleW(nullptr),p)){result=ERROR_ACCESS_DENIED;goto end;}bool ok=!fixture?(!_wcsicmp(p,EXPLORER_PATH)&&hashMatches(p,EXPLORER_SHA)):((!_wcsicmp(p,FIXTURE_PATH)&&hashMatches(p,FIXTURE_SHA))||(!_wcsicmp(p,UNIT_PATH)&&hashMatches(p,UNIT_SHA)));
#ifdef THEME_MENU_UNIT
  // Compiled only into the non-UI unit EXE; absent from production DLL.
  if(fixture){HMODULE here=nullptr;ok=GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(PCWSTR)&initialize,&here)&&here==GetModuleHandleW(nullptr);}
#endif
  if(!ok){result=ERROR_ACCESS_DENIED;goto end;}}
 {HIGHCONTRASTW h={sizeof(h)};if(GetDpiForSystem()!=96||!SystemParametersInfoW(SPI_GETHIGHCONTRAST,sizeof(h),&h,0)||(h.dwFlags&HCF_HIGHCONTRASTON)){result=ERROR_NOT_SUPPORTED;goto end;}}
 if(!currentPath()||!hashMatches(OLD_AERO_PATH,OLD_AERO_SHA)){result=ERROR_REVISION_MISMATCH;goto end;}
 {PCWSTR paths[]={UX_PATH,PCS_PATH,SHELL_PATH};const char* hashes[]={UX_SHA,PCS_SHA,SHELL_SHA};for(int i=0;i<3;i++){if(!hashMatches(paths[i],hashes[i])){result=ERROR_REVISION_MISMATCH;goto end;}modules[i]=LoadLibraryExW(paths[i],nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if(!modules[i]||!mapped(modules[i],paths[i])){result=ERROR_REVISION_MISMATCH;goto end;}}}
 if(memcmp((BYTE*)modules[0]+0x609c0,fromDataGuard,32)||memcmp((BYTE*)modules[0]+0x37f70,getClassGuard,32)){result=ERROR_REVISION_MISMATCH;goto end;}
 fromData=(FromData)((BYTE*)modules[0]+0x609c0);getClass=(GetClass)((BYTE*)modules[0]+0x37f70);
 for(int i=0;i<8;i++)real[i]=(BYTE*)modules[0]+apiRvas[i];
 retained=OpenThemeData(nullptr,L"Menu");app=*(void**)((BYTE*)modules[0]+0x9cab8);if(!retained||!app){result=ERROR_INVALID_DATA;goto end;}oldFile=*(void**)((BYTE*)app+8);
 {void*f=nullptr;if(FAILED(fromData(retained,&f))||f!=oldFile){result=ERROR_REVISION_MISMATCH;goto end;}COLORREF color=0;if(((ColorFn)real[6])(retained,27,1,3803,&color)!=HRESULT_FROM_WIN32(ERROR_NOT_FOUND)||FAILED(((ColorFn)real[6])(retained,14,1,3803,&color))){result=ERROR_REVISION_MISMATCH;goto end;}}
 ThemeMenuState.oldFile=(ULONGLONG)oldFile;ThemeMenuState.app=(ULONGLONG)app;ThemeMenuState.ux=(ULONGLONG)modules[0];ThemeMenuState.pcs=(ULONGLONG)modules[1];ThemeMenuState.shell=(ULONGLONG)modules[2];ThemeMenuState.oldReference=(ULONGLONG)retained;ThemeMenuState.callTable=(ULONGLONG)calls;ThemeMenuState.codeSites=17;
 ThemeMenuState.processDpiBefore=(ULONGLONG)GetDpiAwarenessContextForProcess(GetCurrentProcess());ThemeMenuState.threadDpiBefore=(ULONGLONG)GetThreadDpiAwarenessContext();
 for(int i=0;i<17;i++){auto&d=siteDefs[i];BYTE*address=(BYTE*)modules[d.module]+d.rva;if(memcmp(address,d.expected,d.length)||memcmp(address-16,d.context,32)){result=ERROR_REVISION_MISMATCH;goto end;}}
 for(int i=0;i<3;i++){islands[i]=nearPage((BYTE*)modules[i]);if(!islands[i]){result=ERROR_NOT_ENOUGH_MEMORY;goto end;}}
 for(int i=0;i<17;i++){auto&d=siteDefs[i];auto&r=calls[i];r.module=d.module;r.rva=d.rva;r.length=d.length;r.api=d.api;r.address=(ULONGLONG)((BYTE*)modules[d.module]+d.rva);r.thunk=(ULONGLONG)(islands[d.module]+i*16);BYTE*t=(BYTE*)r.thunk;t[0]=0x48;t[1]=0xb8;memcpy(t+2,&wrappers[d.api],8);t[10]=0xff;t[11]=0xe0;memcpy(r.original,d.expected,d.length);memset(r.replacement,0x90,8);r.replacement[0]=0xe8;int64_t diff=(int64_t)r.thunk-(int64_t)(r.address+5);if(diff<INT32_MIN||diff>INT32_MAX){result=ERROR_INVALID_ADDRESS;goto end;}int32_t rel=(int32_t)diff;memcpy(r.replacement+1,&rel,4);MEMORY_BASIC_INFORMATION m={};if(!VirtualQuery((void*)r.address,&m,sizeof(m))){result=GetLastError();goto end;}r.protection=m.Protect;}
 for(int i=0;i<3;i++){DWORD old;if(!VirtualProtect(islands[i],4096,PAGE_EXECUTE_READ,&old)||!FlushInstructionCache(GetCurrentProcess(),islands[i],4096)){result=ERROR_WRITE_FAULT;goto end;}}
 {HMODULE self;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(PCWSTR)&initialize,&self)){result=GetLastError();goto end;}}
 // Entry-held own-process installation only: no UI callbacks may run while bytes publish.
 for(auto&r:calls){DWORD old,ignore;if(!VirtualProtect((void*)r.address,r.length,PAGE_EXECUTE_READWRITE,&old)){result=GetLastError();break;}memcpy((void*)r.address,r.replacement,r.length);r.published=1;BOOL flushed=FlushInstructionCache(GetCurrentProcess(),(void*)r.address,r.length),protectedAgain=VirtualProtect((void*)r.address,r.length,r.protection,&ignore);if(!flushed||!protectedAgain||memcmp((void*)r.address,r.replacement,r.length)){result=ERROR_WRITE_FAULT;break;}}
 if(result){terminalFailure=true;ThemeMenuState.quarantined=1;goto end;}installed=true;ThemeMenuState.active=1;
 ThemeMenuState.processDpiAfter=(ULONGLONG)GetDpiAwarenessContextForProcess(GetCurrentProcess());ThemeMenuState.threadDpiAfter=(ULONGLONG)GetThreadDpiAwarenessContext();
 if(!AreDpiAwarenessContextsEqual((DPI_AWARENESS_CONTEXT)ThemeMenuState.processDpiBefore,(DPI_AWARENESS_CONTEXT)ThemeMenuState.processDpiAfter)||!AreDpiAwarenessContextsEqual((DPI_AWARENESS_CONTEXT)ThemeMenuState.threadDpiBefore,(DPI_AWARENESS_CONTEXT)ThemeMenuState.threadDpiAfter)){result=ERROR_NOT_SUPPORTED;terminalFailure=true;ThemeMenuState.quarantined=1;}
end:if(result&&!installed&&!ThemeMenuState.quarantined&&retained){CloseThemeData(retained);retained=nullptr;ThemeMenuState.oldReference=0;}ThemeMenuState.result=result;ReleaseSRWLockExclusive(&gate);return result;}
extern "C" __declspec(dllexport) DWORD WINAPI ThemeMenuInitialize(void*){return initialize(false);}
extern "C" __declspec(dllexport) DWORD WINAPI ThemeMenuFixtureInitialize(void*){return initialize(true);}
extern "C" __declspec(dllexport) DWORD WINAPI ThemeMenuRestore(void*){AcquireSRWLockExclusive(&gate);DWORD r=restoreLocked();ThemeMenuState.result=r;ReleaseSRWLockExclusive(&gate);return r;}
