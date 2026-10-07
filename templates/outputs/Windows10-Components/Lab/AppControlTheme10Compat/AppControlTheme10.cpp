#include <windows.h>
#include <uxtheme.h>
#include <bcrypt.h>
#include <psapi.h>
#include <stdlib.h>
#include "../Theme10BrowserProbe/HashCheck.hpp"
#include "Pins.h"
using OpenFn=HTHEME(WINAPI*)(HWND,PCWSTR);
using OpenDpiFn=HTHEME(WINAPI*)(HWND,PCWSTR,UINT);
using FileOpenFn=HRESULT(WINAPI*)(void*,HANDLE,HANDLE,void**);
using FileCloseFn=void(WINAPI*)(void*,void*);
using DataOpenFn=HTHEME(WINAPI*)(void*,HWND,PCWSTR,int);
using CreateFn=HRESULT(WINAPI*)(void*,PWSTR,UINT,int,PWSTR,UINT,int,int);
using LoadFn=HRESULT(WINAPI*)(HANDLE,HMODULE,PCWSTR,PCWSTR,PCWSTR,HANDLE*,PWSTR,UINT,HANDLE*,PWSTR,UINT,CreateFn,HANDLE*,USHORT,int);
struct STATE {DWORD size,version,result,active,opens,passed,dpiRejected,classRejected,button,edit,combo,oldFailed,restores,quarantined,retained;ULONGLONG file,current,slots[2],original[2],replacement[2];};
extern "C" __declspec(dllexport) STATE ControlTheme10State={sizeof(STATE),1};
static SRWLOCK gate=SRWLOCK_INIT;
static HMODULE ux,cc;static HTHEME retainNative;static void*app,*file,*baseline;
static OpenFn nativeOpen;static OpenDpiFn nativeDpi;static DataOpenFn openFileData;
static bool installed,terminalFailure;static DWORD protections[2];static bool pagePending[2];
static void**slots[2];static void*original[2];
static bool mapped(HMODULE module,PCWSTR expected){
 WCHAR physical[32768],wanted[32768],disk[32768];
 if(!K32GetMappedFileNameW(GetCurrentProcess(),module,physical,32768))return false;
 WCHAR drive[]={expected[0],L':',0};if(!QueryDosDeviceW(drive,disk,32768))return false;
 if(wcslen(disk)+wcslen(expected+2)>=32768)return false;wcscpy(wanted,disk);wcscat(wanted,expected+2);return !_wcsicmp(physical,wanted);
}
static bool guarded(BYTE*base,const GUARD*g,size_t n){for(size_t i=0;i<n;i++)if(memcmp(base+g[i].rva,g[i].bytes,g[i].size))return false;return true;}
static bool currentUnchanged(){return app&&*(void**)((BYTE*)app+8)==baseline;}
static int eligible(HWND hwnd,PCWSTR classes,UINT dpi){
 DWORD pid=0;WCHAR cls[128];if(!hwnd||GetWindowThreadProcessId(hwnd,&pid)!=GetCurrentThreadId()||pid!=GetCurrentProcessId()||!GetClassNameW(hwnd,cls,128)||!classes){InterlockedIncrement((LONG*)&ControlTheme10State.classRejected);return 0;}
 HIGHCONTRASTW hc={sizeof(hc)};if(!SystemParametersInfoW(SPI_GETHIGHCONTRAST,sizeof(hc),&hc,0)||(hc.dwFlags&HCF_HIGHCONTRASTON)){InterlockedIncrement((LONG*)&ControlTheme10State.classRejected);return 0;}
 int kind=!_wcsicmp(cls,L"Button")?1:!_wcsicmp(cls,L"Edit")?2:!_wcsicmp(cls,L"ComboBox")?3:0;
 PCWSTR expected=kind==1?L"Button":kind==2?L"Edit":kind==3?L"ComboBox":L"";
 if(!kind||_wcsicmp(classes,expected)){InterlockedIncrement((LONG*)&ControlTheme10State.classRejected);return 0;}
 UINT actual=GetDpiForWindow(hwnd);if(actual!=96||(dpi&&dpi!=96)){InterlockedIncrement((LONG*)&ControlTheme10State.dpiRejected);return 0;}
 return kind;
}
static HTHEME tryOld(HWND hwnd,PCWSTR classes,UINT dpi){
 if(!installed||!currentUnchanged())return nullptr;int kind=eligible(hwnd,classes,dpi);if(!kind)return nullptr;
 HTHEME h=openFileData(file,hwnd,classes,1);
 if(h){InterlockedIncrement((LONG*)&ControlTheme10State.opens);InterlockedIncrement((LONG*)(kind==1?&ControlTheme10State.button:kind==2?&ControlTheme10State.edit:&ControlTheme10State.combo));}
 else InterlockedIncrement((LONG*)&ControlTheme10State.oldFailed);
 return h;
}
static HTHEME WINAPI hookOpen(HWND w,PCWSTR cls){AcquireSRWLockShared(&gate);HTHEME h=tryOld(w,cls,0);ReleaseSRWLockShared(&gate);if(h)return h;InterlockedIncrement((LONG*)&ControlTheme10State.passed);return nativeOpen(w,cls);}
static HTHEME WINAPI hookDpi(HWND w,PCWSTR cls,UINT dpi){AcquireSRWLockShared(&gate);HTHEME h=tryOld(w,cls,dpi);ReleaseSRWLockShared(&gate);if(h)return h;InterlockedIncrement((LONG*)&ControlTheme10State.passed);return nativeDpi(w,cls,dpi);}
static void*replacement[2]={(void*)hookOpen,(void*)hookDpi};
static void releaseProvider(){
 if(file){((FileCloseFn)((BYTE*)ux+0x2c210))(app,file);file=nullptr;}
 if(retainNative){CloseThemeData(retainNative);retainNative=nullptr;}
 // Native modules and this helper remain pinned because previously opened HTHEME
 // objects can still exist. Their own native CloseThemeData owns their references.
}
static DWORD loadProvider(){
 retainNative=nativeOpen(nullptr,L"Button");if(!retainNative)return ERROR_NOT_SUPPORTED;
 app=*(void**)((BYTE*)ux+0x9cab8);if(!app)return ERROR_INVALID_DATA;baseline=*(void**)((BYTE*)app+8);
 HANDLE source=CreateFileW(OLD_AERO,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);if(source==INVALID_HANDLE_VALUE)return GetLastError();
 HANDLE shared=nullptr,nonshared=nullptr;HRESULT hr=((LoadFn)((BYTE*)ux+0x4720))(source,nullptr,OLD_AERO,L"NormalColor",L"NormalSize",&shared,nullptr,0,&nonshared,nullptr,0,nullptr,nullptr,0,0);CloseHandle(source);
 if(FAILED(hr)||!shared||!nonshared){if(shared)CloseHandle(shared);if(nonshared)CloseHandle(nonshared);return FAILED(hr)?(DWORD)hr:ERROR_INVALID_DATA;}
 if(!currentUnchanged()){CloseHandle(shared);CloseHandle(nonshared);return ERROR_REVISION_MISMATCH;}
 hr=((FileOpenFn)((BYTE*)ux+0xa7f8))(app,shared,nonshared,&file);
 if(FAILED(hr)||!file){
  // Native failure can consume either/both handles. Never blind-close numeric
  // values after that call. Startup is terminal and the launcher must abort the
  // exact new owned host; process teardown releases any unconsumed handles.
  ControlTheme10State.quarantined=1;terminalFailure=true;return FAILED(hr)?(DWORD)hr:ERROR_INVALID_DATA;
 }
 ControlTheme10State.file=(ULONGLONG)file;ControlTheme10State.current=(ULONGLONG)baseline;
 return currentUnchanged()?0:ERROR_REVISION_MISMATCH;
}
static DWORD restoreLocked(){
 for(int i=0;i<2;i++)if(slots[i]&&*slots[i]!=original[i]&&*slots[i]!=replacement[i])return ERROR_BUSY;
 installed=false;ControlTheme10State.active=0;
 DWORD result=0;
 for(int i=1;i>=0;i--)if(slots[i]&&(*slots[i]==replacement[i]||pagePending[i])){
  DWORD old;if(!VirtualProtect(slots[i],8,PAGE_READWRITE,&old)){result=GetLastError();continue;}
  if(*slots[i]==replacement[i])InterlockedCompareExchangePointer(slots[i],original[i],replacement[i]);
  DWORD ignored;if(!VirtualProtect(slots[i],8,protections[i],&ignored))result=GetLastError();else pagePending[i]=false;
  if(*slots[i]!=original[i])result=ERROR_BUSY;
 }
 if(!result){ControlTheme10State.restores++;releaseProvider();}else terminalFailure=true;
 return result;
}
struct AppInput {DWORD size,version;WCHAR path[32768];CHAR sha[65];};
extern "C" __declspec(dllexport) DWORD AppThemeInputSize=sizeof(AppInput);
static DWORD initialize(bool fixture,const AppInput*input=nullptr){
 AcquireSRWLockExclusive(&gate);DWORD result=0;
 if(terminalFailure){result=ERROR_INVALID_STATE;goto end;}
 if(installed){if(!currentUnchanged()){result=ERROR_BUSY;goto end;}for(int i=0;i<2;i++)if(*slots[i]!=replacement[i])result=ERROR_BUSY;goto end;}
 if(terminalFailure){result=ERROR_INVALID_STATE;goto end;}
 {WCHAR path[32768];if(!GetModuleFileNameW(nullptr,path,32768)||!mapped(GetModuleHandleW(nullptr),path)){result=ERROR_ACCESS_DENIED;goto end;}bool okay=fixture?(!_wcsicmp(path,FIXTURE_PATH)&&hashMatches(path,FIXTURE_SHA)):(input&&input->size==sizeof(AppInput)&&input->version==1&&input->path[32767]==0&&input->sha[64]==0&&!_wcsicmp(path,input->path)&&hashMatches(path,input->sha));if(!okay){result=ERROR_ACCESS_DENIED;goto end;}}
 if(GetDpiForSystem()!=96){result=ERROR_NOT_SUPPORTED;goto end;}
 if(!hashMatches(UX_PATH,UX_SHA)||!hashMatches(CC_PATH,CC_SHA)||!hashMatches(OLD_AERO,OLD_AERO_SHA)){result=ERROR_REVISION_MISMATCH;goto end;}
 ux=LoadLibraryExW(UX_PATH,nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);cc=LoadLibraryExW(CC_PATH,nullptr,0);
 if(!ux||!cc||!mapped(ux,UX_PATH)||!mapped(cc,CC_PATH)||!guarded((BYTE*)ux,uxGuards,_countof(uxGuards))||!guarded((BYTE*)cc,ccGuards,_countof(ccGuards))){result=ERROR_REVISION_MISMATCH;goto end;}
 nativeOpen=(OpenFn)GetProcAddress(ux,"OpenThemeData");nativeDpi=(OpenDpiFn)GetProcAddress(ux,"OpenThemeDataForDpi");openFileData=(DataOpenFn)GetProcAddress(ux,MAKEINTRESOURCEA(16));
 if((BYTE*)nativeOpen!=(BYTE*)ux+OPEN_RVA||(BYTE*)nativeDpi!=(BYTE*)ux+DPI_RVA||(BYTE*)openFileData!=(BYTE*)ux+0x493f0){result=ERROR_REVISION_MISMATCH;goto end;}
 for(int i=0;i<2;i++){
  slots[i]=(void**)((BYTE*)cc+(i?0x243550:0x243450));original[i]=i?(void*)nativeDpi:(void*)nativeOpen;
  if(*slots[i]!=(i?(void*)nativeDpi:(void*)nativeOpen)){
   if(*slots[i]!=(BYTE*)cc+thunks[i]){result=ERROR_BUSY;goto end;}
   HTHEME h=i?((OpenDpiFn)*slots[i])(nullptr,L"Button",96):((OpenFn)*slots[i])(nullptr,L"Button");if(h)CloseThemeData(h);
   if(*slots[i]!=original[i]){result=ERROR_BUSY;goto end;}
  }
  MEMORY_BASIC_INFORMATION info={};if(!VirtualQuery(slots[i],&info,sizeof(info))){result=GetLastError();goto end;}protections[i]=info.Protect;
  ControlTheme10State.slots[i]=(ULONGLONG)slots[i];ControlTheme10State.original[i]=(ULONGLONG)original[i];ControlTheme10State.replacement[i]=(ULONGLONG)replacement[i];
 }
 result=loadProvider();if(result)goto end;
 {HMODULE self=nullptr;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(PCWSTR)&initialize,&self)){result=GetLastError();goto end;}}
 for(int i=0;i<2;i++){
  DWORD old;if(!VirtualProtect(slots[i],8,PAGE_READWRITE,&old)){result=GetLastError();break;}pagePending[i]=true;
  void*found=InterlockedCompareExchangePointer(slots[i],replacement[i],original[i]);DWORD ignored;
  BOOL okay=VirtualProtect(slots[i],8,protections[i],&ignored);if(okay)pagePending[i]=false;
  if(found!=original[i]||!okay||*slots[i]!=replacement[i]){result=ERROR_WRITE_FAULT;break;}
 }
 if(result){terminalFailure=true;restoreLocked();goto end;}
 installed=true;ControlTheme10State.active=1;ControlTheme10State.retained=1;
end:
 if(result&&!installed&&!ControlTheme10State.quarantined)releaseProvider();
 ControlTheme10State.result=result;ReleaseSRWLockExclusive(&gate);return result;
}
extern "C" __declspec(dllexport) DWORD WINAPI ControlTheme10Initialize(void*input){return initialize(false,(AppInput*)input);}
extern "C" __declspec(dllexport) DWORD WINAPI ControlTheme10FixtureInitialize(void*){return initialize(true);}
extern "C" __declspec(dllexport) DWORD WINAPI ControlTheme10Restore(void*){AcquireSRWLockExclusive(&gate);DWORD r=restoreLocked();ControlTheme10State.result=r;ReleaseSRWLockExclusive(&gate);return r;}
BOOL WINAPI DllMain(HINSTANCE,DWORD,void*){return TRUE;}

struct AppVisualState {DWORD size,version,controls,oldControls,nativeControls,refreshQueued,errors,reserved;};
extern "C" __declspec(dllexport) AppVisualState AppThemeVisualState={sizeof(AppVisualState),1};
static BOOL CALLBACK appChild(HWND w,LPARAM refresh){DWORD pid=0;GetWindowThreadProcessId(w,&pid);WCHAR cls[128];if(pid!=GetCurrentProcessId()||!GetClassNameW(w,cls,128))return TRUE;
if(_wcsicmp(cls,L"Button")&&_wcsicmp(cls,L"Edit")&&_wcsicmp(cls,L"ComboBox"))return TRUE;
if(refresh){if(PostMessageW(w,WM_THEMECHANGED,0,0))AppThemeVisualState.refreshQueued++;else AppThemeVisualState.errors++;return TRUE;}
AppThemeVisualState.controls++;return TRUE;}
static BOOL CALLBACK appTop(HWND w,LPARAM refresh){DWORD pid=0;GetWindowThreadProcessId(w,&pid);if(pid==GetCurrentProcessId()){appChild(w,refresh);EnumChildWindows(w,appChild,refresh);}return TRUE;}
extern "C" __declspec(dllexport) DWORD WINAPI AppThemeRefresh(void*){AcquireSRWLockShared(&gate);if(!installed||!currentUnchanged()){ReleaseSRWLockShared(&gate);return ERROR_INVALID_STATE;}AppThemeVisualState.refreshQueued=0;AppThemeVisualState.errors=0;EnumWindows(appTop,1);DWORD result=AppThemeVisualState.errors?ERROR_WRITE_FAULT:0;ReleaseSRWLockShared(&gate);return result;}
extern "C" __declspec(dllexport) DWORD WINAPI AppThemeReadback(void*){AcquireSRWLockShared(&gate);if(!installed||!currentUnchanged()){ReleaseSRWLockShared(&gate);return ERROR_INVALID_STATE;}AppThemeVisualState.controls=AppThemeVisualState.oldControls=AppThemeVisualState.nativeControls=0;EnumWindows(appTop,0);ReleaseSRWLockShared(&gate);return 0;}
