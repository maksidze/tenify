#define THEME_MENU_UNIT
#include "ThemeMenu.cpp"
#include <stdio.h>
static FILE*logFile;static bool good=true;
static void check(const char*label,bool v){fprintf(logFile,"%s %s\n",label,v?"PASS":"FAIL");fflush(logFile);good&=v;}
struct UnitThemeParams{DWORD Size,Reserved04;PCWSTR Path,Color,SizeName;DWORD Reserved20,Dpi,ConnectedDpi[7],Flags,HighContrast,Reserved4c;void*ThemeFile;};
using ThemeCreateFn=HRESULT(WINAPI*)(void*,PWSTR,UINT,int,PWSTR,UINT,int,int);
using ThemeLoadFn=HRESULT(WINAPI*)(HANDLE,HMODULE,PCWSTR,PCWSTR,PCWSTR,HANDLE*,PWSTR,UINT,HANDLE*,PWSTR,UINT,ThemeCreateFn,HANDLE*,USHORT,int);
using ThemeOpenFn=HRESULT(WINAPI*)(void*,HANDLE,HANDLE,void**);using ThemeDataOpenFn=HTHEME(WINAPI*)(void*,HWND,PCWSTR,int);using ThemeCloseFn=void(WINAPI*)(void*,void*);
static bool loadTheme(HMODULE ux,PCWSTR path){UnitThemeParams p={};p.Size=sizeof(p);p.Path=path;p.Color=L"NormalColor";p.SizeName=L"NormalSize";return SUCCEEDED(((HRESULT(WINAPI*)(UnitThemeParams*))((BYTE*)ux+0x5f7c0))(&p))&&p.ThemeFile;}
static bool changeByte(BYTE*p,BYTE value){DWORD old,ignore;if(!VirtualProtect(p,1,PAGE_EXECUTE_READWRITE,&old))return false;*p=value;BOOL a=FlushInstructionCache(GetCurrentProcess(),p,1),b=VirtualProtect(p,1,old,&ignore);return a&&b;}
static HRESULT query(HTHEME h,int part,int state,int property,COLORREF*out,bool scoped=true){ReadLock lock;int mapped=mapPart(h,part,state,scoped?(void*)(calls[0].address+5):nullptr);return mapped<0?E_HANDLE:((ColorFn)real[6])(h,mapped,state,property,out);}
static DWORD WINAPI watch(void*p){if(WaitForSingleObject((HANDLE)p,18000)==WAIT_TIMEOUT)ExitProcess(0xdeca);return 0;}
int wmain(int argc,wchar_t**argv){if(argc!=3)return 2;logFile=_wfopen(argv[1],L"w");if(!logFile)return 3;HANDLE done=CreateEventW(nullptr,TRUE,FALSE,nullptr),watcher=CreateThread(nullptr,0,watch,done,0,nullptr);if(!done||!watcher)return 4;
 check("PMv2",SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2));HMODULE ux=LoadLibraryExW(UX_PATH,nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);check("native hash",ux&&hashMatches(UX_PATH,UX_SHA)&&mapped(ux,UX_PATH));if(!good)return 5;
 check("production initializer wrong EXE refuses",initialize(false)==ERROR_ACCESS_DENIED);
 if(!wcscmp(argv[2],L"native")){check("fixture native theme refused",initialize(true)==ERROR_REVISION_MISMATCH);goto finish;}
 {HTHEME warm=OpenThemeData(nullptr,L"Button");if(warm)CloseThemeData(warm);}check("own full old theme",loadTheme(ux,OLD_AERO_PATH));if(!good)return 6;
 if(!wcscmp(argv[2],L"wrong-byte")){BYTE*p=(BYTE*)ux+siteDefs[0].rva,b=*p;check("own wrong byte",changeByte(p,b^1));check("byte guard refuses",initialize(true)==ERROR_REVISION_MISMATCH);check("no publication",ThemeMenuState.active==0&&calls[0].published==0);check("repair own deliberate byte",changeByte(p,b));goto finish;}
 check("initialize",initialize(true)==0&&ThemeMenuState.active==1);check("idempotence",initialize(true)==0);if(!good)return 7;
 {
  HTHEME menu=OpenThemeData(nullptr,L"MENU"),dark=OpenThemeData(nullptr,L"DarkMode_ImmersiveStart::MENU"),button=OpenThemeData(nullptr,L"Button");check("genuine handles",menu&&dark&&button);
  struct Guard{DWORD before;COLORREF color;DWORD after;};
  for(HTHEME h:{menu,dark})for(int state=0;state<=4;state++){Guard actual={0x11223344,0x12345678,0x55667788};COLORREF expected=0x12345678;HRESULT a=query(h,27,state,3803,&actual.color),b=((ColorFn)real[6])(h,14,state,3803,&expected);check("MENU27 maps genuine14 state0..4",a==b&&SUCCEEDED(a)&&actual.color==expected&&actual.before==0x11223344&&actual.after==0x55667788);}
  for(int state:{1,5}){Guard actual={0x11223344,0x12345678,0x55667788};COLORREF expected=0x12345678;HRESULT a=query(button,27,state,3803,&actual.color),b=((ColorFn)real[6])(button,27,state,3803,&expected);check("nonMENU unchanged",a==b&&actual.color==expected&&actual.before==0x11223344&&actual.after==0x55667788);}
  {Guard v={0x11223344,0x12345678,0x55667788};check("unscoped original missing result",query(menu,27,1,3803,&v.color,false)==HRESULT_FROM_WIN32(ERROR_NOT_FOUND)&&v.color==0x12345678&&v.before==0x11223344&&v.after==0x55667788);}
  {Guard v={0x11223344,0x12345678,0x55667788};check("reserved state no translation",query(menu,27,5,3803,&v.color)==HRESULT_FROM_WIN32(ERROR_NOT_FOUND)&&v.color==0x12345678);}
  {Guard v={0x11223344,0x12345678,0x55667788};COLORREF expected=0x12345678;HRESULT b=((ColorFn)real[6])(menu,14,1,3817,&expected);check("genuine missing property preserved",query(menu,27,1,3817,&v.color)==b&&v.color==expected);}
  // Open a separate genuine native provider, preserving private old current generation.
  {PCWSTR path=L"C:\\Windows\\Resources\\Themes\\aero\\aero.msstyles";HANDLE input=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr),shared=nullptr,nonshared=nullptr;void*file=nullptr;
   HRESULT hr=((ThemeLoadFn)((BYTE*)ux+0x4720))(input,nullptr,path,L"NormalColor",L"NormalSize",&shared,nullptr,0,&nonshared,nullptr,0,nullptr,nullptr,0,0);CloseHandle(input);check("separate native provider load",SUCCEEDED(hr)&&shared&&nonshared);if(FAILED(hr)||!shared||!nonshared)return 8;
   hr=((ThemeOpenFn)((BYTE*)ux+0xa7f8))(app,shared,nonshared,&file);check("separate native provider open",SUCCEEDED(hr)&&file&&sameGeneration());if(FAILED(hr)||!file)return 9;
   HTHEME native=((ThemeDataOpenFn)((BYTE*)ux+0x493f0))(file,nullptr,L"Menu",1);void*backing=nullptr;check("native different backing",native&&SUCCEEDED(fromData(native,&backing))&&backing==file&&backing!=oldFile);
   Guard v={0x11223344,0x12345678,0x55667788};COLORREF expected=0x12345678;HRESULT a=query(native,27,1,3803,&v.color),b=((ColorFn)real[6])(native,27,1,3803,&expected);check("foreign native MENU unchanged",a==b&&v.color==expected&&v.before==0x11223344&&v.after==0x55667788);CloseThemeData(native);((ThemeCloseFn)((BYTE*)ux+0x2c210))(app,file);
  }
  if(!wcscmp(argv[2],L"generation")){
   DWORD count=ThemeMenuState.generationRejected;check("foreign own generation",loadTheme(ux,L"C:\\Windows\\Resources\\Themes\\aero\\aero.msstyles")&&!sameGeneration());Guard v={0x11223344,0x12345678,0x55667788};check("stale handle rejected before class/fromData",query(menu,27,1,3803,&v.color)==E_HANDLE&&v.color==0x12345678&&v.before==0x11223344&&v.after==0x55667788&&ThemeMenuState.generationRejected==count+1);
   check("foreign restore refused",ThemeMenuRestore(nullptr)==ERROR_BUSY);check("foreign reinit refused",initialize(true)==ERROR_BUSY);check("all 17 patches preserved",[&](){for(auto&r:calls)if(memcmp((void*)r.address,r.replacement,r.length))return false;return true;}());
   // Invalidated theme handles must NOT be closed or dereferenced after forced127.
   fprintf(logFile,"forced generation uses immediate own process teardown; no hot continuation\n");goto finish;
  }
  CloseThemeData(button);CloseThemeData(dark);CloseThemeData(menu);
 }
 {terminalFailure=true;check("quarantined installed helper cannot claim success",initialize(true)==ERROR_INVALID_STATE);terminalFailure=false;}
 {BYTE*p=(BYTE*)calls[0].address,b=*p;check("own foreign call marker",changeByte(p,b^1));check("foreign call reinit refused",initialize(true)==ERROR_BUSY);check("foreign call restore refused",ThemeMenuRestore(nullptr)==ERROR_BUSY);check("foreign call preserved",*p==(BYTE)(b^1));check("repair own marker",changeByte(p,b));}
 check("restore",ThemeMenuRestore(nullptr)==0);check("17 exact original bytes",[&](){for(auto&r:calls)if(r.published||memcmp((void*)r.address,r.original,r.length))return false;return true;}());check("repeat restore safe",ThemeMenuRestore(nullptr)==0);
finish:
 fprintf(logFile,"COMPLETE=%d no HWND, no input, no global theme change\n",good?0:1);fclose(logFile);SetEvent(done);WaitForSingleObject(watcher,1000);CloseHandle(watcher);CloseHandle(done);return good?0:1;
}
