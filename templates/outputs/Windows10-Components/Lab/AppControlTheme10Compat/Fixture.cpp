#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shobjidl.h>
#include <shlobj.h>
#include <uxtheme.h>
#include <stdio.h>
#include <stddef.h>
#include <bcrypt.h>
#include "../Theme10BrowserProbe/HashCheck.hpp"
static FILE*logFile; static HDESK ownedDesktop;
static void logHr(const char*s,HRESULT hr){fprintf(logFile,"%s=%08lx\n",s,hr);fflush(logFile);}
#include "FixtureControls.hpp"
typedef struct{DWORD Size,Reserved04;PCWSTR Path,Color,SizeName;DWORD Reserved20,Dpi,ConnectedDpi[7],Flags,HighContrast,Reserved4c;void*ThemeFile;}ThemeParams;
static_assert(sizeof(ThemeParams)==0x58&&offsetof(ThemeParams,ThemeFile)==0x50,"native loader ABI");
class Events final:public IExplorerBrowserEvents{LONG refs=1;public:bool complete=false,failed=false;HRESULT error=S_OK;HRESULT WINAPI QueryInterface(REFIID id,void**out)override{if(!out)return E_POINTER;*out=nullptr;if(id==IID_IUnknown||id==IID_IExplorerBrowserEvents){*out=this;AddRef();return S_OK;}return E_NOINTERFACE;}ULONG WINAPI AddRef()override{return InterlockedIncrement(&refs);}ULONG WINAPI Release()override{LONG n=InterlockedDecrement(&refs);if(!n)delete this;return n;}HRESULT WINAPI OnNavigationPending(PCIDLIST_ABSOLUTE)override{logHr("OnNavigationPending",S_OK);return S_OK;}HRESULT WINAPI OnViewCreated(IShellView*view)override{logHr("OnViewCreated",view?S_OK:E_POINTER);return S_OK;}HRESULT WINAPI OnNavigationComplete(PCIDLIST_ABSOLUTE)override{complete=true;logHr("OnNavigationComplete",S_OK);return S_OK;}HRESULT WINAPI OnNavigationFailed(PCIDLIST_ABSOLUTE)override{failed=true;logHr("OnNavigationFailed",E_FAIL);return S_OK;}};
static DWORD WINAPI watchdog(void*p){if(WaitForSingleObject((HANDLE)p,16000)==WAIT_TIMEOUT)ExitProcess(0xdeca);return 0;}
static BOOL CALLBACK child(HWND w,LPARAM){wchar_t c[120];GetClassNameW(w,c,120);DWORD pid=0;DWORD tid=GetWindowThreadProcessId(w,&pid);RECT r;GetWindowRect(w,&r);fprintf(logFile,"HWND=%p PID=%lu TID=%lu class=%ls rect=%ld,%ld,%ld,%ld\n",w,pid,tid,c,r.left,r.top,r.right,r.bottom);return TRUE;}
static int runFixture(int argc,wchar_t**argv){if(argc!=5)return 2;logFile=_wfopen(argv[1],L"w");if(!logFile)return 3;bool old=!wcscmp(argv[2],L"old");int code=1;HRESULT hr;IExplorerBrowser*browser=nullptr;Events*events=nullptr;DWORD cookie=0;HWND owner=nullptr;PIDLIST_ABSOLUTE pidl=nullptr;bool com=false;HANDLE stop=CreateEventW(nullptr,TRUE,FALSE,nullptr),watch=CreateThread(nullptr,0,watchdog,stop,0,nullptr);if(!watch)return 4;
 HDESK prior=GetThreadDesktop(GetCurrentThreadId());wchar_t deskName[100];swprintf(deskName,100,L"ThemeBrowserOwn-%lu-%llu",GetCurrentProcessId(),GetTickCount64());HDESK desk=CreateDesktopW(deskName,nullptr,nullptr,0,GENERIC_ALL,nullptr);ownedDesktop=desk;if(!desk||!SetThreadDesktop(desk))return 5;
 fprintf(logFile,"PID=%lu TID=%lu mode=%ls privateDesktop=%ls neverSwitched=1\n",GetCurrentProcessId(),GetCurrentThreadId(),argv[2],deskName);fflush(logFile);
 do{
  if(!controlsContext())break;
  hr=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE);logHr("CoInitializeEx",hr);if(FAILED(hr))break;com=true;
  wchar_t theme[1024],color[100],size[100];hr=GetCurrentThemeName(theme,1024,color,100,size,100);logHr("GetCurrentThemeName",hr);fprintf(logFile,"theme=%ls\n",theme);fflush(logFile);
  WNDCLASSW c={};c.lpfnWndProc=DefWindowProcW;c.hInstance=GetModuleHandleW(nullptr);c.lpszClassName=L"Theme10BrowserProbeOwn";RegisterClassW(&c);owner=CreateWindowExW(WS_EX_TOOLWINDOW,c.lpszClassName,L"Own isolated folder fixture",WS_OVERLAPPEDWINDOW|WS_VISIBLE,0,0,800,600,nullptr,nullptr,c.hInstance,nullptr);if(!owner)break;
  if(!controlsStart(owner))break;
  hr=CoCreateInstance(CLSID_ExplorerBrowser,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&browser));logHr("CoCreateInstance ExplorerBrowser INPROC",hr);if(FAILED(hr)||!browser)break;
  FOLDERSETTINGS settings={FVM_DETAILS,FWF_AUTOARRANGE};RECT bounds={0,0,780,560};hr=browser->Initialize(owner,&bounds,&settings);logHr("ExplorerBrowser Initialize",hr);if(FAILED(hr))break;
  hr=browser->SetOptions(EBO_NOTRAVELLOG|EBO_NOBORDER);logHr("SetOptions",hr);if(FAILED(hr))break;events=new Events;hr=browser->Advise(events,&cookie);logHr("Advise",hr);if(FAILED(hr))break;
  hr=SHParseDisplayName(argv[3],nullptr,&pidl,0,nullptr);logHr("Parse own folder",hr);if(FAILED(hr))break;hr=browser->BrowseToIDList(pidl,SBSP_ABSOLUTE);logHr("BrowseToIDList",hr);if(FAILED(hr))break;
  ULONGLONG deadline=GetTickCount64()+6000;while(!events->complete&&!events->failed&&GetTickCount64()<deadline){MSG m;while(PeekMessageW(&m,nullptr,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessageW(&m);}MsgWaitForMultipleObjectsEx(0,nullptr,30,QS_ALLINPUT,MWMO_INPUTAVAILABLE);}
  fprintf(logFile,"navigationComplete=%d failed=%d\n",events->complete,events->failed);fflush(logFile);IFolderView*view=nullptr;hr=browser->GetCurrentView(IID_PPV_ARGS(&view));logHr("GetCurrentView",hr);int count=-1;bool folderMatched=false;
  if(SUCCEEDED(hr)&&view){ULONGLONG enumDeadline=GetTickCount64()+6000;do{hr=view->ItemCount(SVGIO_ALLVIEW,&count);if(FAILED(hr)||count>=1)break;MSG m;while(PeekMessageW(&m,nullptr,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessageW(&m);}MsgWaitForMultipleObjectsEx(0,nullptr,30,QS_ALLINPUT,MWMO_INPUTAVAILABLE);}while(GetTickCount64()<enumDeadline);logHr("ItemCount",hr);fprintf(logFile,"itemCount=%d\n",count);IPersistFolder2*folder=nullptr;hr=view->GetFolder(IID_PPV_ARGS(&folder));if(SUCCEEDED(hr)&&folder){PIDLIST_ABSOLUTE current=nullptr;hr=folder->GetCurFolder(&current);folderMatched=SUCCEEDED(hr)&&ILIsEqual(pidl,current);CoTaskMemFree(current);folder->Release();}view->Release();}
  child(owner,0);EnumChildWindows(owner,child,0);fprintf(logFile,"folderMatched=%d\n",folderMatched);if(events->complete&&!events->failed&&count>=1&&folderMatched)code=0;
 }while(false);
 if(browser){if(cookie)browser->Unadvise(cookie);logHr("Destroy browser",browser->Destroy());browser->Release();}if(events)events->Release();CoTaskMemFree(pidl);if(!controlsStop())code=1;if(owner)DestroyWindow(owner);if(com)CoUninitialize();fprintf(logFile,"workerDesktopReleasedByThreadExit=1\n");SetEvent(stop);WaitForSingleObject(watch,1000);CloseHandle(watch);CloseHandle(stop);fprintf(logFile,"COMPLETE exit=%d no global shell activation or input\n",code);fclose(logFile);return code;
}
struct Input { int argc; wchar_t** argv; };
static DWORD WINAPI fixtureThread(void* arg){Input*p=(Input*)arg;return runFixture(p->argc,p->argv);}
int wmain(int argc,wchar_t**argv){
 if(argc!=5)return 2;Input input={argc,argv};HANDLE t=CreateThread(nullptr,0,fixtureThread,&input,0,nullptr);if(!t)return 6;
 if(WaitForSingleObject(t,20000)!=WAIT_OBJECT_0)ExitProcess(0xdecb);
 DWORD code=1;GetExitCodeThread(t,&code);CloseHandle(t);BOOL closed=ownedDesktop&&CloseDesktop(ownedDesktop);
 FILE*f=_wfopen(argv[1],L"a");if(f){fprintf(f,"workerExited=1 desktopCloseAfterThreadExit=%d error=%lu\n",closed,closed?0:GetLastError());fclose(f);}return closed?(int)code:7;
}