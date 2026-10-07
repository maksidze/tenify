#include <windows.h>
#include <uxtheme.h>
#include <bcrypt.h>
#include <psapi.h>
#include <stdlib.h>
#include <stddef.h>
#include <initializer_list>
#include "../Theme10BrowserProbe/HashCheck.hpp"
#include "Pins.h"
using DpiFn=HTHEME(WINAPI*)(HWND,PCWSTR,UINT);
using ColorFn=HRESULT(WINAPI*)(HTHEME,int,int,int,COLORREF*);
using FileOpenFn=HRESULT(WINAPI*)(void*,HANDLE,HANDLE,void**);
using FileCloseFn=void(WINAPI*)(void*,void*);
using DataOpenFn=HTHEME(WINAPI*)(void*,HWND,PCWSTR,int);
using FromDataFn=HRESULT(WINAPI*)(HTHEME,void**);
using CreateFn=HRESULT(WINAPI*)(void*,PWSTR,UINT,int,PWSTR,UINT,int,int);
using LoadFn=HRESULT(WINAPI*)(HANDLE,HMODULE,PCWSTR,PCWSTR,PCWSTR,HANDLE*,PWSTR,UINT,HANDLE*,PWSTR,UINT,CreateFn,HANDLE*,USHORT,int);
struct ThemeParams{DWORD Size,Reserved04;PCWSTR Path,Color,SizeName;DWORD Reserved20,Dpi,ConnectedDpi[7],Flags,HighContrast,Reserved4c;void*ThemeFile;};
static_assert(sizeof(ThemeParams)==0x58&&offsetof(ThemeParams,ThemeFile)==0x50,"theme ABI");
using FullLoadFn=HRESULT(WINAPI*)(ThemeParams*);
struct STATE{DWORD size,version,result,active,fullTheme,fallback8,fallback11,passed,tracked,rejected,failures,restores,quarantined,dpiStable,nativeHeaderFallbacks,generationRejected;ULONGLONG oldFile,nativeFile,slots[2],original[2],replacement[2],processDpiBefore,processDpiAfter,threadDpiBefore,threadDpiAfter;};
extern "C" __declspec(dllexport) STATE ThemeFolderHybridState={sizeof(STATE),2};
static SRWLOCK gate=SRWLOCK_INIT;static HMODULE ux,dui;static DpiFn nativeDpi;static ColorFn nativeColor;static FromDataFn fromData;
static HTHEME retainedOld,nativeHeader,held[128];static unsigned heldCount,heldLimit=128;static void*app,*oldFile,*nativeFile;static bool installed,terminalFailure;
static void**slots[2];static void*original[2];static DWORD protection[2];static bool pending[2];
static bool mapped(HMODULE m,PCWSTR expected){WCHAR actual[32768],disk[32768],want[32768],drive[]={expected[0],L':',0};if(!K32GetMappedFileNameW(GetCurrentProcess(),m,actual,32768)||!QueryDosDeviceW(drive,disk,32768)||wcslen(disk)+wcslen(expected+2)>=32768)return false;wcscpy(want,disk);wcscat(want,expected+2);return !_wcsicmp(actual,want);}
static bool guarded(BYTE*b,const GUARD*g,size_t n){for(size_t i=0;i<n;i++)if(memcmp(b+g[i].rva,g[i].bytes,g[i].size))return false;return true;}
static bool isTracked(HTHEME h){for(unsigned i=0;i<heldCount;i++)if(held[i]==h)return true;return false;}
static bool sameGeneration(){return app&&*(void**)((BYTE*)app+8)==oldFile;}
static HTHEME WINAPI hookDpi(HWND w,PCWSTR c,UINT dpi){
 HTHEME h=nativeDpi(w,c,dpi);if(!h)return h;
 AcquireSRWLockExclusive(&gate);
 DWORD pid=0;if(w)GetWindowThreadProcessId(w,&pid);
 if(installed&&c&&!wcscmp(c,L"ItemsViewAccessible::Header")&&dpi==96&&(!w||(pid==GetCurrentProcessId()&&GetDpiForWindow(w)==96))&&!isTracked(h)){
  void*backing=nullptr;HRESULT hr=fromData(h,&backing);
  if(!sameGeneration()){ThemeFolderHybridState.generationRejected++;ReleaseSRWLockExclusive(&gate);return h;}
  bool retained=false;
  if(SUCCEEDED(hr)&&backing==oldFile&&heldCount<heldLimit){
   HTHEME own=nativeDpi(w,c,dpi); // Retain a genuine reference, preventing handle reuse after the caller closes.
   if(own==h){held[heldCount++]=own;ThemeFolderHybridState.tracked=heldCount;retained=true;}
   else{if(own)CloseThemeData(own);ThemeFolderHybridState.rejected++;}
  }else ThemeFolderHybridState.rejected++;
  if(!retained&&SUCCEEDED(hr)&&backing==oldFile){
   // Exact class, known incompatible old backing, 96 DPI only. No unbounded map:
   // a genuine native class handle is a functional fallback when retention is exhausted.
   HTHEME native=((DataOpenFn)((BYTE*)ux+0x493f0))(nativeFile,w,c,1);
   if(native){CloseThemeData(h);h=native;ThemeFolderHybridState.nativeHeaderFallbacks++;}
   else ThemeFolderHybridState.failures++;
  }
 }
 ReleaseSRWLockExclusive(&gate);return h;
}
static HRESULT WINAPI hookColor(HTHEME h,int part,int state,int property,COLORREF*out){
 AcquireSRWLockShared(&gate);
 // Test-loader generation changes can invalidate ordinary HTHEME values despite
 // retained references. Never dereference a known old handle after that change.
 // This is an explicit failure; the owner must discard this host, not hot-repair UI.
 if(installed&&isTracked(h)&&!sameGeneration()){InterlockedIncrement((LONG*)&ThemeFolderHybridState.generationRejected);ReleaseSRWLockShared(&gate);return E_HANDLE;}
 HRESULT hr=nativeColor(h,part,state,property,out);
 if(installed&&hr==HRESULT_FROM_WIN32(ERROR_NOT_FOUND)&&isTracked(h)&&part==1&&(state==8||state==11)&&property==3803){
  void*backing=nullptr;
  if(sameGeneration()&&SUCCEEDED(fromData(h,&backing))&&backing==oldFile){
   hr=nativeColor(nativeHeader,part,state,property,out);
   if(SUCCEEDED(hr))InterlockedIncrement((LONG*)(state==8?&ThemeFolderHybridState.fallback8:&ThemeFolderHybridState.fallback11));
   else InterlockedIncrement((LONG*)&ThemeFolderHybridState.failures);
  }else InterlockedIncrement((LONG*)&ThemeFolderHybridState.generationRejected);
 }else InterlockedIncrement((LONG*)&ThemeFolderHybridState.passed);
 ReleaseSRWLockShared(&gate);return hr;
}
static void*replacement[]={(void*)hookDpi,(void*)hookColor};
static void releaseProvider(){
 for(unsigned i=0;i<heldCount;i++)CloseThemeData(held[i]);heldCount=0;
 if(nativeHeader){CloseThemeData(nativeHeader);nativeHeader=nullptr;}
 if(nativeFile){((FileCloseFn)((BYTE*)ux+0x2c210))(app,nativeFile);nativeFile=nullptr;}
 if(retainedOld){CloseThemeData(retainedOld);retainedOld=nullptr;}
 // Keep modules and this helper pinned: in-flight native callers may still hold a function pointer.
}
static DWORD fullTheme(PCWSTR path){
 ThemeParams p={};p.Size=sizeof(p);p.Path=path;p.Color=L"NormalColor";p.SizeName=L"NormalSize";
 HRESULT hr=((FullLoadFn)((BYTE*)ux+0x5f7c0))(&p);if(FAILED(hr)||!p.ThemeFile)return FAILED(hr)?(DWORD)hr:ERROR_INVALID_DATA;
 WCHAR observed[32768],color[100],size[100];hr=GetCurrentThemeName(observed,32768,color,100,size,100);
 return SUCCEEDED(hr)&&!_wcsicmp(path,observed)&&!wcscmp(color,L"NormalColor")&&!wcscmp(size,L"NormalSize")?0:ERROR_REVISION_MISMATCH;
}
static DWORD loadProvider(){
 retainedOld=nativeDpi(nullptr,L"Button",96);if(!retainedOld)return ERROR_INVALID_DATA;
 app=*(void**)((BYTE*)ux+0x9cab8);if(!app)return ERROR_INVALID_DATA;oldFile=*(void**)((BYTE*)app+8);
 HANDLE input=CreateFileW(NATIVE_AERO_PATH,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);if(input==INVALID_HANDLE_VALUE)return GetLastError();
 HANDLE shared=nullptr,nonshared=nullptr;HRESULT hr=((LoadFn)((BYTE*)ux+0x4720))(input,nullptr,NATIVE_AERO_PATH,L"NormalColor",L"NormalSize",&shared,nullptr,0,&nonshared,nullptr,0,nullptr,nullptr,0,0);CloseHandle(input);
 if(FAILED(hr)||!shared||!nonshared){if(shared)CloseHandle(shared);if(nonshared)CloseHandle(nonshared);return FAILED(hr)?(DWORD)hr:ERROR_INVALID_DATA;}
 if(*(void**)((BYTE*)app+8)!=oldFile){CloseHandle(shared);CloseHandle(nonshared);return ERROR_REVISION_MISMATCH;}
 hr=((FileOpenFn)((BYTE*)ux+0xa7f8))(app,shared,nonshared,&nativeFile);
 if(FAILED(hr)||!nativeFile){ThemeFolderHybridState.quarantined=1;terminalFailure=true;return FAILED(hr)?(DWORD)hr:ERROR_INVALID_DATA;}
 nativeHeader=((DataOpenFn)((BYTE*)ux+0x493f0))(nativeFile,nullptr,L"ItemsViewAccessible::Header",1);
 HTHEME own=nativeDpi(nullptr,L"ItemsViewAccessible::Header",96);void*backing=nullptr;
 if(!nativeHeader||!own){if(own)CloseThemeData(own);return ERROR_INVALID_DATA;}
 held[heldCount++]=own;ThemeFolderHybridState.tracked=heldCount;
 if(FAILED(fromData(nativeHeader,&backing))||backing!=nativeFile||FAILED(fromData(own,&backing))||backing!=oldFile)return ERROR_REVISION_MISMATCH;
 for(int s:{8,11}){COLORREF c=0;hr=nativeColor(own,1,s,3803,&c);if(hr!=HRESULT_FROM_WIN32(ERROR_NOT_FOUND)||FAILED(nativeColor(nativeHeader,1,s,3803,&c)))return ERROR_REVISION_MISMATCH;}
 ThemeFolderHybridState.oldFile=(ULONGLONG)oldFile;ThemeFolderHybridState.nativeFile=(ULONGLONG)nativeFile;
 return *(void**)((BYTE*)app+8)==oldFile?0:ERROR_REVISION_MISMATCH;
}
static DWORD restoreLocked(){
 for(int i=0;i<2;i++)if(slots[i]&&original[i]&&*slots[i]!=original[i]&&*slots[i]!=replacement[i])return ERROR_BUSY;
 // Restore native theme before disabling fallback. Only our unchanged private old theme may be restored.
 if(ThemeFolderHybridState.fullTheme){WCHAR path[32768],c[100],s[100];if(!sameGeneration()||FAILED(GetCurrentThemeName(path,32768,c,100,s,100))||_wcsicmp(path,OLD_AERO_PATH)||wcscmp(c,L"NormalColor")||wcscmp(s,L"NormalSize"))return ERROR_BUSY;DWORD r=fullTheme(NATIVE_AERO_PATH);if(r)return r;ThemeFolderHybridState.fullTheme=0;}
 installed=false;ThemeFolderHybridState.active=0;DWORD result=0;
 for(int i=1;i>=0;i--)if(slots[i]&&original[i]&&(*slots[i]==replacement[i]||pending[i])){
  DWORD old;if(!VirtualProtect(slots[i],8,PAGE_READWRITE,&old)){result=GetLastError();continue;}
  if(*slots[i]==replacement[i]&&InterlockedCompareExchangePointer(slots[i],original[i],replacement[i])!=replacement[i])result=ERROR_BUSY;
  DWORD ignore;if(!VirtualProtect(slots[i],8,protection[i],&ignore))result=GetLastError();else pending[i]=false;
  if(*slots[i]!=original[i])result=ERROR_BUSY;
 }
 if(!result){releaseProvider();ThemeFolderHybridState.restores++;}else terminalFailure=true;
 return result;
}
static DWORD initialize(bool fixture){
 AcquireSRWLockExclusive(&gate);DWORD result=0;
 if(installed){for(int i=0;i<2;i++)if(*slots[i]!=replacement[i])result=ERROR_BUSY;if(!app||*(void**)((BYTE*)app+8)!=oldFile)result=ERROR_BUSY;goto end;}
 if(terminalFailure){result=ERROR_INVALID_STATE;goto end;}
 {WCHAR path[32768];if(!GetModuleFileNameW(nullptr,path,32768)||_wcsicmp(path,fixture?FIXTURE_PATH:EXPLORER_PATH)||!hashMatches(path,fixture?FIXTURE_SHA:EXPLORER_SHA)||!mapped(GetModuleHandleW(nullptr),path)){result=ERROR_ACCESS_DENIED;goto end;}}
 {HIGHCONTRASTW h={sizeof(h)};if(GetDpiForSystem()!=96||!SystemParametersInfoW(SPI_GETHIGHCONTRAST,sizeof(h),&h,0)||(h.dwFlags&HCF_HIGHCONTRASTON)){result=ERROR_NOT_SUPPORTED;goto end;}}
 if(!hashMatches(UX_PATH,UX_SHA)||!hashMatches(DUI_PATH,DUI_SHA)||!hashMatches(OLD_AERO_PATH,OLD_AERO_SHA)||!hashMatches(NATIVE_AERO_PATH,NATIVE_AERO_SHA)){result=ERROR_REVISION_MISMATCH;goto end;}
 ux=LoadLibraryExW(UX_PATH,nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);dui=LoadLibraryExW(DUI_PATH,nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
 if(!ux||!dui||!mapped(ux,UX_PATH)||!mapped(dui,DUI_PATH)||!guarded((BYTE*)ux,uxGuards,_countof(uxGuards))||!guarded((BYTE*)dui,duiGuards,_countof(duiGuards))){result=ERROR_REVISION_MISMATCH;goto end;}
 nativeDpi=(DpiFn)GetProcAddress(ux,"OpenThemeDataForDpi");nativeColor=(ColorFn)GetProcAddress(ux,"GetThemeColor");fromData=(FromDataFn)GetProcAddress(ux,MAKEINTRESOURCEA(17));
 if((BYTE*)nativeDpi!=(BYTE*)ux+DPI_RVA||(BYTE*)nativeColor!=(BYTE*)ux+COLOR_RVA||(BYTE*)fromData!=(BYTE*)ux+0x609c0){result=ERROR_REVISION_MISMATCH;goto end;}
 for(int i=0;i<2;i++){
  slots[i]=(void**)((BYTE*)dui+(i?0x197398:0x1973b8));original[i]=i?(void*)nativeColor:(void*)nativeDpi;
  if(*slots[i]!=original[i]){
   if(*slots[i]!=(BYTE*)dui+thunks[i]){result=ERROR_BUSY;goto end;}
   if(i){COLORREF c=0;((ColorFn)*slots[i])(nullptr,1,8,3803,&c);}else{HTHEME h=((DpiFn)*slots[i])(nullptr,L"Button",96);if(h)CloseThemeData(h);}
   if(*slots[i]!=original[i]){result=ERROR_BUSY;goto end;}
  }
  MEMORY_BASIC_INFORMATION info={};if(!VirtualQuery(slots[i],&info,sizeof(info))){result=GetLastError();goto end;}protection[i]=info.Protect;
  ThemeFolderHybridState.slots[i]=(ULONGLONG)slots[i];ThemeFolderHybridState.original[i]=(ULONGLONG)original[i];ThemeFolderHybridState.replacement[i]=(ULONGLONG)replacement[i];
 }
 {WCHAR p[32768],c[100],s[100];if(FAILED(GetCurrentThemeName(p,32768,c,100,s,100))||_wcsicmp(p,NATIVE_AERO_PATH)||wcscmp(c,L"NormalColor")||wcscmp(s,L"NormalSize")){result=ERROR_NOT_SUPPORTED;goto end;}}
 ThemeFolderHybridState.processDpiBefore=(ULONGLONG)GetDpiAwarenessContextForProcess(GetCurrentProcess());ThemeFolderHybridState.threadDpiBefore=(ULONGLONG)GetThreadDpiAwarenessContext();
 {HTHEME warm=nativeDpi(nullptr,L"Button",96);if(!warm){result=ERROR_INVALID_DATA;goto end;}CloseThemeData(warm);}
 result=fullTheme(OLD_AERO_PATH);if(result){terminalFailure=true;goto end;}ThemeFolderHybridState.fullTheme=1;
 result=loadProvider();if(result){terminalFailure=true;goto end;}
 ThemeFolderHybridState.processDpiAfter=(ULONGLONG)GetDpiAwarenessContextForProcess(GetCurrentProcess());ThemeFolderHybridState.threadDpiAfter=(ULONGLONG)GetThreadDpiAwarenessContext();
 ThemeFolderHybridState.dpiStable=AreDpiAwarenessContextsEqual((DPI_AWARENESS_CONTEXT)ThemeFolderHybridState.processDpiBefore,(DPI_AWARENESS_CONTEXT)ThemeFolderHybridState.processDpiAfter)&&AreDpiAwarenessContextsEqual((DPI_AWARENESS_CONTEXT)ThemeFolderHybridState.threadDpiBefore,(DPI_AWARENESS_CONTEXT)ThemeFolderHybridState.threadDpiAfter);
 if(!ThemeFolderHybridState.dpiStable){result=ERROR_NOT_SUPPORTED;terminalFailure=true;goto end;}
 {HMODULE self;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(PCWSTR)&initialize,&self)){result=GetLastError();terminalFailure=true;goto end;}}
 for(int i=0;i<2;i++){DWORD old;if(!VirtualProtect(slots[i],8,PAGE_READWRITE,&old)){result=GetLastError();break;}pending[i]=true;void*found=InterlockedCompareExchangePointer(slots[i],replacement[i],original[i]);DWORD ignore;BOOL ok=VirtualProtect(slots[i],8,protection[i],&ignore);if(ok)pending[i]=false;if(found!=original[i]||!ok||*slots[i]!=replacement[i]){result=ERROR_WRITE_FAULT;break;}}
 if(result){terminalFailure=true;restoreLocked();goto end;}
 installed=true;ThemeFolderHybridState.active=1;
end:
 if(result&&!installed&&!ThemeFolderHybridState.fullTheme&&!ThemeFolderHybridState.quarantined)releaseProvider();
 ThemeFolderHybridState.result=result;ReleaseSRWLockExclusive(&gate);return result;
}
extern "C" __declspec(dllexport) DWORD WINAPI ThemeFolderHybridInitialize(void*){return initialize(false);}
extern "C" __declspec(dllexport) DWORD WINAPI ThemeFolderHybridFixtureInitialize(void*){return initialize(true);}
extern "C" __declspec(dllexport) DWORD WINAPI ThemeFolderHybridRestore(void*){AcquireSRWLockExclusive(&gate);DWORD r=restoreLocked();ThemeFolderHybridState.result=r;ReleaseSRWLockExclusive(&gate);return r;}
// Only hash-pinned own fixture may force the capacity branch. No production caller can use it.
extern "C" __declspec(dllexport) DWORD WINAPI ThemeFolderHybridFixtureSetCapacity(void*limit){
 WCHAR path[32768];if(!GetModuleFileNameW(nullptr,path,32768)||_wcsicmp(path,FIXTURE_PATH)||!hashMatches(path,FIXTURE_SHA))return ERROR_ACCESS_DENIED;
 size_t n=(size_t)limit;if(n>_countof(held))return ERROR_INVALID_PARAMETER;
 AcquireSRWLockExclusive(&gate);for(unsigned i=0;i<heldCount;i++)CloseThemeData(held[i]);heldCount=0;heldLimit=(unsigned)n;ThemeFolderHybridState.tracked=0;ReleaseSRWLockExclusive(&gate);return 0;
}
BOOL WINAPI DllMain(HINSTANCE,DWORD,void*){return TRUE;}
