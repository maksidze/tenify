#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <roapi.h>
#include <winstring.h>
#include <objbase.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>
typedef struct {float X,Y,Width,Height;} Rect;
typedef struct {UINT64 MonitorId;HSTRING PersistentDeviceId;double RawPixelsPerViewPixel;Rect DisplayArea,WorkArea,DynamicSafeWorkArea,StaticSafeWorkArea;BYTE IsPrimary;BYTE Padding[7];} Monitor;
_Static_assert(sizeof(Monitor)==96,"Exact native IDL size");
typedef struct Object{void**vt;} Object;
typedef ULONG(WINAPI*ReleaseFn)(Object*);
typedef HRESULT(WINAPI*FactoryFn)(Object*,UINT,Monitor*,Object**);
// Native IDL takes the 96-byte ABI struct by value; x64 passes a caller-owned temporary indirectly.
typedef HRESULT(WINAPI*UpdateFn)(Object*,Monitor);
typedef HRESULT(WINAPI*RemoveFn)(Object*,UINT64);
static HRESULT(WINAPI*createString)(PCNZWCH,UINT32,HSTRING*);
static HRESULT(WINAPI*deleteString)(HSTRING);
static HRESULT(WINAPI*initialize)(RO_INIT_TYPE);
static void(WINAPI*uninitialize)(void);
static HRESULT(WINAPI*getFactory)(HSTRING,REFIID,void**);
static FILE*logFile;
static Monitor monitors[32];static UINT count;static BOOL failed;
typedef struct {HANDLE Ready;DWORD Milliseconds;} Watchdog;
static DWORD WINAPI watchdog(void*arg){Watchdog*w=arg;SetEvent(w->Ready);Sleep(w->Milliseconds);TerminateProcess(GetCurrentProcess(),0xdeca);return 0;}
static BOOL startWatchdog(Watchdog*w,DWORD ms){w->Ready=CreateEventW(NULL,TRUE,FALSE,NULL);w->Milliseconds=ms;if(!w->Ready)return FALSE;HANDLE thread=CreateThread(NULL,0,watchdog,w,0,NULL);if(!thread)return FALSE;BOOL ready=WaitForSingleObject(w->Ready,5000)==WAIT_OBJECT_0;CloseHandle(thread);return ready;}
static void release(Object*o){if(o)((ReleaseFn)o->vt[2])(o);}
static void clean(Monitor*a,UINT n){for(UINT i=0;i<n;i++)if(a[i].PersistentDeviceId)deleteString(a[i].PersistentDeviceId);}
static Rect rect(RECT r){return(Rect){(float)r.left,(float)r.top,(float)(r.right-r.left),(float)(r.bottom-r.top)};}
static BOOL deviceId(PCWSTR device,HSTRING*out){
 DISPLAY_DEVICEW d={.cb=sizeof(d)};const WCHAR*id=L"";
 if(EnumDisplayDevicesW(device,0,&d,EDD_GET_DEVICE_INTERFACE_NAME)){
  if(d.StateFlags&2){if(d.DeviceID[0])id=d.DeviceID;
   else{ZeroMemory(&d,sizeof(d));d.cb=sizeof(d);if(EnumDisplayDevicesW(device,0,&d,0))id=d.DeviceID[0]?d.DeviceID:d.DeviceKey;}}
 }
 return SUCCEEDED(createString(id,(UINT32)wcslen(id),out));
}
static BOOL CALLBACK enumerate(HMONITOR h,HDC dc,LPRECT bounds,LPARAM data){
 if(count==32){failed=TRUE;return FALSE;}MONITORINFOEXW mi={.cbSize=sizeof(mi)};if(!GetMonitorInfoW(h,(MONITORINFO*)&mi)){failed=TRUE;return FALSE;}
 UINT x=0,y=0;typedef HRESULT(WINAPI*DpiFn)(HMONITOR,int,UINT*,UINT*);static DpiFn dpi;if(!dpi)dpi=(DpiFn)GetProcAddress(LoadLibraryW(L"shcore.dll"),"GetDpiForMonitor");
 if(!dpi||FAILED(dpi(h,0,&x,&y))||!x||x!=y){failed=TRUE;return FALSE;}
 Monitor*m=&monitors[count];ZeroMemory(m,sizeof(*m));m->MonitorId=(UINT64)(uintptr_t)h;m->RawPixelsPerViewPixel=x/96.0;m->DisplayArea=rect(mi.rcMonitor);m->WorkArea=rect(mi.rcWork);m->DynamicSafeWorkArea=m->StaticSafeWorkArea=m->WorkArea;m->IsPrimary=(BYTE)((mi.dwFlags&MONITORINFOF_PRIMARY)!=0);
 if(!deviceId(mi.szDevice,&m->PersistentDeviceId)){failed=TRUE;return FALSE;}++count;
 fwprintf(logFile,L"MONITOR id=%llx dpi=%u primary=%u device=%ls area=%ld,%ld,%ld,%ld work=%ld,%ld,%ld,%ld\n",m->MonitorId,x,m->IsPrimary,mi.szDevice,mi.rcMonitor.left,mi.rcMonitor.top,mi.rcMonitor.right,mi.rcMonitor.bottom,mi.rcWork.left,mi.rcWork.top,mi.rcWork.right,mi.rcWork.bottom);fflush(logFile);return TRUE;
}
static BOOL inventory(void){count=0;failed=FALSE;APPBARDATA a={.cbSize=sizeof(a)};UINT_PTR state=SHAppBarMessage(ABM_GETSTATE,&a);fwprintf(logFile,L"APPBAR state=%llu\n",(unsigned long long)state);if(state&ABS_AUTOHIDE){fwprintf(logFile,L"REFUSE autohide\n");return FALSE;}return EnumDisplayMonitors(NULL,NULL,enumerate,0)&&!failed&&count>0;}
static BOOL identity(HANDLE h,DWORD pid,ULONGLONG born,PCWSTR path){
 FILETIME b,e,k,u;WCHAR observed[32768];DWORD n=32768,owner=0;HWND shell=GetShellWindow();GetWindowThreadProcessId(shell,&owner);
 return owner==pid&&WaitForSingleObject(h,0)==WAIT_TIMEOUT&&GetProcessTimes(h,&b,&e,&k,&u)&&(*(ULONGLONG*)&b)==born&&QueryFullProcessImageNameW(h,0,observed,&n)&&!_wcsicmp(path,observed);
}
int wmain(int argc,WCHAR**argv){
 // Default invocation is inert. --inventory uses read-only monitor APIs only.
 if(argc<3)return 64;logFile=_wfopen(argv[2],L"w, ccs=UTF-8");if(!logFile)return 65;
 HMODULE rt=LoadLibraryW(L"combase.dll");createString=(void*)GetProcAddress(rt,"WindowsCreateString");deleteString=(void*)GetProcAddress(rt,"WindowsDeleteString");initialize=(void*)GetProcAddress(rt,"RoInitialize");uninitialize=(void*)GetProcAddress(rt,"RoUninitialize");getFactory=(void*)GetProcAddress(rt,"RoGetActivationFactory");if(!createString||!deleteString||!initialize||!uninitialize||!getFactory)return 66;
 if(!SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2))return 73;
 if(!_wcsicmp(argv[1],L"--inventory")){BOOL ok=inventory();clean(monitors,count);fclose(logFile);return ok?0:67;}
 if(!_wcsicmp(argv[1],L"--watchdog-proof")){Watchdog w;if(!startWatchdog(&w,1000))return 74;Sleep(INFINITE);return 75;}
 if(wcscmp(argv[1],L"--run")||argc!=7)return 68;
 DWORD pid=wcstoul(argv[3],NULL,10);ULONGLONG born=wcstoull(argv[4],NULL,10);DWORD seconds=wcstoul(argv[6],NULL,10);if(!pid||!born||seconds<1||seconds>3600)return 69;
 HANDLE target=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);if(!target||!identity(target,pid,born,argv[5]))return 70;
 HANDLE exclusive=CreateMutexW(NULL,FALSE,L"Local\\Explorer10DisplayMonitorPublisherNative");if(!exclusive)return 76;DWORD lock=WaitForSingleObject(exclusive,0);if(lock!=WAIT_OBJECT_0&&lock!=WAIT_ABANDONED)return 77;
 // Independent own-process watchdog is ready BEFORE any activation or private COM call.
 // Process death releases this native mutex even if the PowerShell supervisor disappears.
 Watchdog w;if(!startWatchdog(&w,(seconds+10)*1000))return 74;
 HRESULT hr=initialize(RO_INIT_MULTITHREADED);if(FAILED(hr))return 71;
 Object*factory=NULL,*server=NULL;HSTRING name=NULL;static const GUID iid={0x1f60c91e,0xa4df,0x5c89,{0x94,0x7c,0x7a,0x3a,0x46,0x21,0x93,0x3b}};
 if(!inventory()){hr=E_FAIL;goto end;}if(!identity(target,pid,born,argv[5])){hr=E_ABORT;goto end;}
 const WCHAR*className=L"WindowsUdk.UI.Shell.DisplayMonitorInfoCollectionServer";
 hr=createString(className,(UINT32)wcslen(className),&name);if(FAILED(hr))goto end;
 hr=getFactory(name,&iid,(void**)&factory);fwprintf(logFile,L"FACTORY hr=%08lx\n",hr);fflush(logFile);if(SUCCEEDED(hr)&&!factory)hr=E_UNEXPECTED;if(FAILED(hr))goto end;
 HMODULE udk=GetModuleHandleW(L"windowsudk.shellcommon.dll");WCHAR physical[32768];if(!udk||!GetModuleFileNameW(udk,physical,32768)||_wcsicmp(physical,L"C:\\Windows\\System32\\windowsudk.shellcommon.dll")||(BYTE*)factory->vt[6]!=(BYTE*)udk+0x24ff0){hr=E_NOINTERFACE;goto end;}
 hr=((FactoryFn)factory->vt[6])(factory,count,monitors,&server);fwprintf(logFile,L"SERVER hr=%08lx pointer=%p\n",hr,server);fflush(logFile);if(SUCCEEDED(hr)&&!server)hr=E_UNEXPECTED;if(FAILED(hr))goto end;
 if((BYTE*)server->vt[6]!=(BYTE*)udk+0x38fd0){hr=E_NOINTERFACE;goto end;}
 // Real factory duplicates input strings. Keep initial inventory only to detect monitor topology changes.
 ULONGLONG deadline=GetTickCount64()+1000ULL*seconds;
 while(GetTickCount64()<deadline&&identity(target,pid,born,argv[5])){if(WaitForSingleObject(target,500)==WAIT_OBJECT_0)break;Monitor prior[32];UINT oldCount=count;CopyMemory(prior,monitors,sizeof(prior));ZeroMemory(monitors,sizeof(monitors));count=0;
  if(!inventory()){clean(prior,oldCount);hr=E_ABORT;break;}BOOL same=count==oldCount;for(UINT i=0;i<count&&same;i++){BOOL found=FALSE;for(UINT j=0;j<oldCount;j++)if(monitors[i].MonitorId==prior[j].MonitorId)found=TRUE;same=found;}
  clean(prior,oldCount);if(!same){hr=E_ABORT;fwprintf(logFile,L"REFUSE topology changed\n");break;}
  if(!identity(target,pid,born,argv[5])){hr=E_ABORT;break;}
  for(UINT i=0;i<count;i++){hr=((UpdateFn)server->vt[6])(server,monitors[i]);if(FAILED(hr))break;}if(FAILED(hr))break;
 }
end:
 fwprintf(logFile,L"RELEASE hr=%08lx targetStillOwned=%u\n",hr,target&&identity(target,pid,born,argv[5]));fflush(logFile);release(server);release(factory);if(name)deleteString(name);clean(monitors,count);uninitialize();if(target)CloseHandle(target);CloseHandle(w.Ready);ReleaseMutex(exclusive);CloseHandle(exclusive);fclose(logFile);return FAILED(hr)?72:0;
}
