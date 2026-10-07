#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shobjidl.h>
#include <shlobj.h>
struct State {DWORD size,version,result,complete,thread,navComplete,navFailed,itemCount,folderMatched,defViews,directViews,reserved;};
extern "C" __declspec(dllexport) State ControlBrowserState={sizeof(State),1};
extern "C" __declspec(dllexport) WCHAR ControlBrowserDesktop[256]={};
class Events final:public IExplorerBrowserEvents{LONG refs=1;public:bool complete=false,failed=false;HRESULT WINAPI QueryInterface(REFIID id,void**out)override{if(!out)return E_POINTER;*out=nullptr;if(id==IID_IUnknown||id==IID_IExplorerBrowserEvents){*out=this;AddRef();return S_OK;}return E_NOINTERFACE;}ULONG WINAPI AddRef()override{return InterlockedIncrement(&refs);}ULONG WINAPI Release()override{LONG n=InterlockedDecrement(&refs);if(!n)delete this;return n;}HRESULT WINAPI OnNavigationPending(PCIDLIST_ABSOLUTE)override{return S_OK;}HRESULT WINAPI OnViewCreated(IShellView*)override{return S_OK;}HRESULT WINAPI OnNavigationComplete(PCIDLIST_ABSOLUTE)override{complete=true;return S_OK;}HRESULT WINAPI OnNavigationFailed(PCIDLIST_ABSOLUTE)override{failed=true;return S_OK;}};
static void pump(){MSG m;while(PeekMessageW(&m,nullptr,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessageW(&m);}MsgWaitForMultipleObjectsEx(0,nullptr,30,QS_ALLINPUT,MWMO_INPUTAVAILABLE);}
static BOOL CALLBACK child(HWND hwnd,LPARAM){WCHAR name[128];GetClassNameW(hwnd,name,128);if(!wcscmp(name,L"SHELLDLL_DefView"))ControlBrowserState.defViews++;if(!wcscmp(name,L"DirectUIHWND"))ControlBrowserState.directViews++;return TRUE;}
extern "C" __declspec(dllexport) DWORD WINAPI ControlBrowserProbe(void*arg){
 auto&s=ControlBrowserState;s.thread=GetCurrentThreadId();s.result=E_FAIL;HRESULT hr=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE);if(FAILED(hr)){s.result=hr;s.complete=1;return s.result;}
 WNDCLASSW c={};c.lpfnWndProc=DefWindowProcW;c.hInstance=GetModuleHandleW(nullptr);c.lpszClassName=L"ControlThemeOwnedBrowser";RegisterClassW(&c);HWND owner=CreateWindowExW(WS_EX_TOOLWINDOW,c.lpszClassName,L"Own private desktop navigation",WS_OVERLAPPEDWINDOW|WS_VISIBLE,0,0,800,600,nullptr,nullptr,c.hInstance,nullptr);
 IExplorerBrowser*browser=nullptr;Events*events=nullptr;DWORD cookie=0;PIDLIST_ABSOLUTE pidl=nullptr;IFolderView*view=nullptr;
 do{
  if(!owner){hr=HRESULT_FROM_WIN32(GetLastError());break;}
  hr=CoCreateInstance(CLSID_ExplorerBrowser,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&browser));if(FAILED(hr))break;
  FOLDERSETTINGS settings={FVM_DETAILS,FWF_AUTOARRANGE};RECT bounds={0,0,780,560};hr=browser->Initialize(owner,&bounds,&settings);if(FAILED(hr))break;
  hr=browser->SetOptions(EBO_NOTRAVELLOG|EBO_NOBORDER);if(FAILED(hr))break;events=new Events;hr=browser->Advise(events,&cookie);if(FAILED(hr))break;
  hr=SHParseDisplayName((PCWSTR)arg,nullptr,&pidl,0,nullptr);if(FAILED(hr))break;hr=browser->BrowseToIDList(pidl,SBSP_ABSOLUTE);if(FAILED(hr))break;
  ULONGLONG end=GetTickCount64()+6000;while(!events->complete&&!events->failed&&GetTickCount64()<end)pump();s.navComplete=events->complete;s.navFailed=events->failed;
  if(!s.navComplete||s.navFailed){hr=E_FAIL;break;}hr=browser->GetCurrentView(IID_PPV_ARGS(&view));if(FAILED(hr))break;
  int count=-1;end=GetTickCount64()+6000;do{hr=view->ItemCount(SVGIO_ALLVIEW,&count);if(FAILED(hr)||count>=1)break;pump();}while(GetTickCount64()<end);s.itemCount=count;
  IPersistFolder2*folder=nullptr;hr=view->GetFolder(IID_PPV_ARGS(&folder));if(SUCCEEDED(hr)&&folder){PIDLIST_ABSOLUTE current=nullptr;hr=folder->GetCurFolder(&current);s.folderMatched=SUCCEEDED(hr)&&ILIsEqual(pidl,current);CoTaskMemFree(current);folder->Release();}
  EnumChildWindows(owner,child,0);hr=s.itemCount>=1&&s.folderMatched&&s.defViews&&s.directViews?S_OK:E_FAIL;
 }while(false);
 if(view)view->Release();if(browser){if(cookie)browser->Unadvise(cookie);browser->Destroy();browser->Release();}if(events)events->Release();CoTaskMemFree(pidl);if(owner)DestroyWindow(owner);CoUninitialize();s.result=hr;s.complete=1;return s.result;
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD why,void*){if(why==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(h);return TRUE;}
extern "C" __declspec(dllexport) DWORD WINAPI ControlBrowserProbeWorker(void*arg){
 struct Input{PCWSTR folder,desktop;};Input*input=(Input*)arg;DWORD bytes=0;
 if(!input||!input->folder||!input->desktop||!GetUserObjectInformationW(GetThreadDesktop(GetCurrentThreadId()),UOI_NAME,ControlBrowserDesktop,sizeof(ControlBrowserDesktop),&bytes)||wcscmp(input->desktop,ControlBrowserDesktop)||(wcsncmp(ControlBrowserDesktop,L"CodexVfsPreflight_",18)&&wcsncmp(ControlBrowserDesktop,L"ControlThemeOwned-",18)))return ERROR_ACCESS_DENIED;
 return ControlBrowserProbe((void*)input->folder);
}
