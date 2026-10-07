#include <commctrl.h>
using InitFn=DWORD(WINAPI*)(void*);
using AnyOpenFn=HTHEME(WINAPI*)(HWND,PCWSTR);
using AnyDpiFn=HTHEME(WINAPI*)(HWND,PCWSTR,UINT);
using FromThemeFn=HRESULT(WINAPI*)(HTHEME,void**);
struct ObservedState{DWORD size,version,result,active,opens,passed,dpiRejected,classRejected,button,edit,combo,oldFailed,restores,quarantined,retained;ULONGLONG file,current,slots[2],original[2],replacement[2];};
static HMODULE helper;static ObservedState*stats;static HWND controls[3];static HWND ownParent;static DWORD beforePixels[3];static void*nativeThemeFiles[3];static bool fixtureOkay=true;static HANDLE context=INVALID_HANDLE_VALUE;static ULONG_PTR contextCookie;
static const wchar_t*classes[]={L"Button",L"Edit",L"ComboBox"};
static bool check(const char*label,bool b){fprintf(logFile,"%s=%s\n",label,b?"PASS":"FAIL");fflush(logFile);if(!b)fixtureOkay=false;return b;}
static bool controlsContext(){
 WCHAR path[32768];GetModuleFileNameW(nullptr,path,32768);wchar_t*slash=wcsrchr(path,L'\\');if(!slash)return false;wcscpy(slash+1,L"Fixture.manifest");ACTCTXW a={sizeof(a)};a.lpSource=path;context=CreateActCtxW(&a);if(context==INVALID_HANDLE_VALUE||!ActivateActCtx(context,&contextCookie))return false;
 HMODULE cc=LoadLibraryW(L"comctl32.dll");if(!cc)return false;using Init=BOOL(WINAPI*)(const INITCOMMONCONTROLSEX*);auto fn=(Init)GetProcAddress(cc,"InitCommonControlsEx");INITCOMMONCONTROLSEX init={sizeof(init),ICC_STANDARD_CLASSES};return fn&&fn(&init);
}
static DWORD paint(HWND hwnd){
 RECT rc;GetClientRect(hwnd,&rc);BITMAPINFO bmi={};bmi.bmiHeader.biSize=40;bmi.bmiHeader.biWidth=rc.right;bmi.bmiHeader.biHeight=-rc.bottom;bmi.bmiHeader.biPlanes=1;bmi.bmiHeader.biBitCount=32;void*bits=nullptr;HDC dc=CreateCompatibleDC(nullptr);HBITMAP bmp=CreateDIBSection(dc,&bmi,DIB_RGB_COLORS,&bits,nullptr,0);if(!bmp||!bits){if(bmp)DeleteObject(bmp);DeleteDC(dc);return 0;}HGDIOBJ prior=SelectObject(dc,bmp);memset(bits,255,rc.right*rc.bottom*4);SendMessageW(hwnd,WM_PRINTCLIENT,(WPARAM)dc,PRF_CLIENT|PRF_ERASEBKGND);GdiFlush();DWORD sum=2166136261u;for(size_t i=0;i<(size_t)rc.right*rc.bottom*4;i++){sum^=((BYTE*)bits)[i];sum*=16777619u;}SelectObject(dc,prior);DeleteObject(bmp);DeleteDC(dc);return sum;
}
static void*backing(HWND w){HMODULE ux=GetModuleHandleW(L"uxtheme.dll");auto fn=(FromThemeFn)GetProcAddress(ux,MAKEINTRESOURCEA(17));HTHEME t=GetWindowTheme(w);void*f=nullptr;if(t)fn(t,&f);return f;}
static HWND makeControl(int n){DWORD style=WS_CHILD|WS_VISIBLE|(n==0?BS_PUSHBUTTON:n==1?ES_AUTOHSCROLL:CBS_DROPDOWN);return CreateWindowExW(n==1?WS_EX_CLIENTEDGE:0,classes[n],n==0?L"Own Button":n==1?L"Own Edit":L"",style,10,10+n*60,220,n==2?160:40,ownParent,(HMENU)(INT_PTR)(200+n),GetModuleHandleW(nullptr),nullptr);}
struct GenericInput {DWORD size,version;WCHAR path[32768];CHAR sha[65];};
static DWORD WINAPI genericOwnInit(void*){GenericInput i={};i.size=sizeof(i);i.version=1;GetModuleFileNameW(nullptr,i.path,32768);if(GetEnvironmentVariableA("APP_THEME_FIXTURE_SHA",i.sha,65)!=64)return ERROR_INVALID_DATA;auto f=(InitFn)GetProcAddress(helper,"ControlTheme10Initialize");return f(&i);}
static bool controlsStart(HWND parent){
 ownParent=parent;for(int n=0;n<3;n++){HWND w=makeControl(n);if(!check("baseline create",w!=nullptr))return false;beforePixels[n]=paint(w);nativeThemeFiles[n]=backing(w);fprintf(logFile,"baseline class=%ls HWND=%p dpi=%u file=%p pixels=%08lx\n",classes[n],w,GetDpiForWindow(w),nativeThemeFiles[n],beforePixels[n]);DestroyWindow(w);}
 HWND existingButton=makeControl(0);DWORD existingPixels=paint(existingButton);
 WCHAR path[32768];GetModuleFileNameW(nullptr,path,32768);wcscpy(wcsrchr(path,L'\\')+1,L"AppControlTheme10.dll");helper=LoadLibraryW(path);if(!check("helper loaded",helper!=nullptr))return false;
 stats=(ObservedState*)GetProcAddress(helper,"ControlTheme10State");auto init=genericOwnInit;auto prod=(InitFn)GetProcAddress(helper,"ControlTheme10Initialize");if(!check("exports",stats&&init&&prod))return false;
 check("production wrong host rejected",prod(nullptr)==ERROR_ACCESS_DENIED);
 BYTE*guard=(BYTE*)GetModuleHandleW(L"uxtheme.dll")+0x4720;BYTE originalByte=*guard;DWORD protection,ignored;
 if(!check("guard page writable",VirtualProtect(guard,1,PAGE_EXECUTE_READWRITE,&protection)!=FALSE))return false;
 *guard=originalByte^1;DWORD refused=init(nullptr);*guard=originalByte;VirtualProtect(guard,1,protection,&ignored);FlushInstructionCache(GetCurrentProcess(),guard,1);check("wrong native instruction refused",refused==ERROR_REVISION_MISMATCH&&!stats->active);
 DWORD r=init(nullptr);fprintf(logFile,"initialize=%08lx active=%lu file=%llx\n",r,stats->active,stats->file);if(!check("initialize scoped",r==0&&stats->active))return false;
 check("initialize idempotent",init(nullptr)==0);
 auto refresh=(InitFn)GetProcAddress(helper,"AppThemeRefresh");check("refresh existing own controls",refresh&&refresh(nullptr)==0);
 MSG ownMessage;while(PeekMessageW(&ownMessage,nullptr,0,0,PM_REMOVE)){TranslateMessage(&ownMessage);DispatchMessageW(&ownMessage);}
 check("existing own Button now old provider",(ULONGLONG)backing(existingButton)==stats->file);check("existing own Button paint changed",paint(existingButton)!=existingPixels);DestroyWindow(existingButton);
 auto restore=(InitFn)GetProcAddress(helper,"ControlTheme10Restore");void**slot=(void**)stats->slots[0];void*replacement=*slot;void*foreign=(BYTE*)stats->original[0]+1;
 if(!check("slot writable",VirtualProtect(slot,8,PAGE_READWRITE,&protection)!=FALSE))return false;
 *slot=foreign;check("foreign retry refused",init(nullptr)==ERROR_BUSY&&*slot==foreign);check("foreign restore refused",restore(nullptr)==ERROR_BUSY&&*slot==foreign);*slot=replacement;VirtualProtect(slot,8,protection,&ignored);check("retry after ownership restored",init(nullptr)==0);
 for(int n=0;n<3;n++){controls[n]=makeControl(n);if(!check("adapted create",controls[n]!=nullptr))return false;DWORD pixels=paint(controls[n]);void*f=backing(controls[n]);fprintf(logFile,"adapted class=%ls HWND=%p dpi=%u file=%p pixels=%08lx oldFile=%d changed=%d\n",classes[n],controls[n],GetDpiForWindow(controls[n]),f,pixels,(ULONGLONG)f==stats->file,pixels!=beforePixels[n]);}
 // Exact HWND scope and DPI fallback, through the actual patched import slots.
 AnyOpenFn open=*(AnyOpenFn*)stats->slots[0];AnyDpiFn dpi=*(AnyDpiFn*)stats->slots[1];auto from=(FromThemeFn)GetProcAddress(GetModuleHandleW(L"uxtheme.dll"),MAKEINTRESOURCEA(17));void*f=nullptr;
 HTHEME h=open(parent,L"Button");if(h){from(h,&f);CloseThemeData(h);}check("foreign class uses native",h&&f&&(ULONGLONG)f!=stats->file);
 f=nullptr;h=dpi(controls[0],L"Button",144);if(h){from(h,&f);CloseThemeData(h);}check("DPI144 uses native",h&&f&&(ULONGLONG)f!=stats->file&&stats->dpiRejected);
 // The direct DPI test changed this own window's cached theme; request the real
 // control's ordinary theme refresh before observing its post-restore state.
 SendMessageW(controls[0],WM_THEMECHANGED,0,0);
 return fixtureOkay;
}
static bool controlsStop(){
 if(helper&&stats&&stats->active){auto restore=(InitFn)GetProcAddress(helper,"ControlTheme10Restore");check("restore import slots",restore&&restore(nullptr)==0&&!stats->active);
  for(int n=0;n<3;n++)if(controls[n]){void*old=backing(controls[n]);DWORD retained=paint(controls[n]);fprintf(logFile,"retained before refresh class=%ls file=%p pixels=%08lx\n",classes[n],old,retained);check("old handle remains usable",old&&(ULONGLONG)old==stats->file&&retained);SendMessageW(controls[n],WM_THEMECHANGED,0,0);DWORD pixels=paint(controls[n]);void*now=backing(controls[n]);fprintf(logFile,"restored class=%ls file=%p pixels=%08lx equalsBaseline=%d\n",classes[n],now,pixels,pixels==beforePixels[n]);check("restored paint baseline",pixels==beforePixels[n]);}
  fprintf(logFile,"stats opens=%lu pass=%lu classes=%lu dpi=%lu button=%lu edit=%lu combo=%lu fail=%lu\n",stats->opens,stats->passed,stats->classRejected,stats->dpiRejected,stats->button,stats->edit,stats->combo,stats->oldFailed);
 }
 for(HWND&w:controls)if(w){DestroyWindow(w);w=nullptr;}if(helper){FreeLibrary(helper);helper=nullptr;}
 if(contextCookie){DeactivateActCtx(0,contextCookie);contextCookie=0;}if(context!=INVALID_HANDLE_VALUE){ReleaseActCtx(context);context=INVALID_HANDLE_VALUE;}return fixtureOkay;
}
