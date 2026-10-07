#define wWinMain FactoryProbeEntry
#include "../NetworkTrayCompat/NetworkFactoryProbe.c"
#undef wWinMain

#include <bcrypt.h>
#include "NetworkTheme.h"
static FILE*networkTrace;
static GUID privateIconGuid;
static volatile LONG realAddSucceeded;
static BOOL privateGuid(void){WCHAR path[32768];DWORD n=GetModuleFileNameW(NULL,path,32768);if(!n||n>=32768)return FALSE;CharUpperBuffW(path,n);BCRYPT_ALG_HANDLE algorithm=NULL;BYTE bytes[32];if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)return FALSE;NTSTATUS status=BCryptHash(algorithm,NULL,0,(BYTE*)path,n*2,bytes,32);BCryptCloseAlgorithmProvider(algorithm,0);if(status<0)return FALSE;memcpy(&privateIconGuid,bytes,16);privateIconGuid.Data3=(privateIconGuid.Data3&0x0fff)|0x5000;privateIconGuid.Data4[0]=(privateIconGuid.Data4[0]&0x3f)|0x80;return TRUE;}
static BOOL(WINAPI*realNotify)(DWORD,PNOTIFYICONDATAW);
static const GUID networkGuid={0x7820ae74,0x23e3,0x4229,{0x82,0xc1,0xe4,0x1c,0xb6,0x7d,0x5b,0x9c}};
static BOOL WINAPI privateNotify(DWORD message,PNOTIFYICONDATAW data){
 NOTIFYICONDATAW adapted={0};PNOTIFYICONDATAW passed=data;BOOL changed=FALSE;
 if(data&&data->cbSize==sizeof(NOTIFYICONDATAW)&&(data->uFlags&NIF_GUID)&&!memcmp(&data->guidItem,&networkGuid,sizeof(GUID))){adapted=*data;adapted.guidItem=privateIconGuid;passed=&adapted;changed=TRUE;}
 HICON recolored=NULL;
 if(changed&&(data->uFlags&NIF_ICON)&&data->hIcon){
  HICON owned=CopyIcon(data->hIcon); // copy FIRST: data may itself refer to our previous saved icon
  if(owned){HICON previous=lastGenuineValid?lastGenuine.hIcon:NULL;lastGenuine=*data;lastGenuine.hIcon=owned;lastGenuineValid=TRUE;adapted.hIcon=owned;if(previous)DestroyIcon(previous);}
  DWORD light=0;if(readSystemLight(&light)){themeLight=light;themeKnown=TRUE;themeContrast=highContrast();recolored=themeIcon(adapted.hIcon,light,themeContrast);if(recolored)adapted.hIcon=recolored;}
 }

 BOOL result=realNotify(message,passed);DWORD error=GetLastError();if(recolored)DestroyIcon(recolored);if(changed&&message==NIM_DELETE){if(lastGenuineValid&&lastGenuine.hIcon)DestroyIcon(lastGenuine.hIcon);lastGenuineValid=FALSE;ZeroMemory(&lastGenuine,sizeof(lastGenuine));}
 if(changed&&message==NIM_ADD&&result)InterlockedExchange(&realAddSucceeded,1);
 if(networkTrace)fprintf(networkTrace,"GenuineNotify msg=%lu return=%d privateNetworkGuid=%d\n",message,result,changed);
 SetLastError(error);return result;
}
static BOOL installPrivateNotify(HMODULE module){
 void**notify=(void**)((BYTE*)module+0x48490);HMODULE shell=GetModuleHandleW(L"shell32.dll");
 void*expected=shell?(void*)GetProcAddress(shell,"Shell_NotifyIconW"):NULL;
 if(!expected||*notify!=expected)return FALSE;
 DWORD old=0,unused=0;realNotify=*notify;
 if(!VirtualProtect(notify,sizeof(void*),PAGE_READWRITE,&old))return FALSE;
 *notify=privateNotify;
 if(!VirtualProtect(notify,sizeof(void*),old,&unused))return FALSE;
 return *notify==(void*)privateNotify;
}

static HANDLE shellProcess;
static DWORD shellPid;
static wchar_t stopFile[32768];
static HANDLE doneEvent;
static volatile LONG stopRequested;
static ULONGLONG hostDeadline;
static BOOL untilStop;
static volatile LONG bootstrapComplete;
static DWORD WINAPI hostWatch(void*x){ULONGLONG stopTick=0;for(;;){if(WaitForSingleObject(doneEvent,200)==WAIT_OBJECT_0)return 0;DWORD pid=0;GetWindowThreadProcessId(GetShellWindow(),&pid);BOOL stop=WaitForSingleObject(shellProcess,0)==WAIT_OBJECT_0||pid!=shellPid||(!bootstrapComplete&&GetTickCount64()>hostDeadline)||(!untilStop&&GetTickCount64()>hostDeadline)||GetFileAttributesW(stopFile)!=INVALID_FILE_ATTRIBUTES;if(stop&&!stopTick){stopTick=GetTickCount64();InterlockedExchange(&stopRequested,1);PostThreadMessageW((DWORD)(ULONG_PTR)x,WM_QUIT,0,0);}if(stopTick&&GetTickCount64()>stopTick+10000)ExitProcess(125);}return 0;}
static ULONGLONG born(HANDLE p){FILETIME a,b,c,d;if(!GetProcessTimes(p,&a,&b,&c,&d))return 0;return((ULONGLONG)a.dwHighDateTime<<32)|a.dwLowDateTime;}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE prev,LPWSTR line,int show){
 int argc;wchar_t**argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(argc==3){LocalFree(argv);return FactoryProbeEntry(h,prev,line,show);}if(argc!=10||(wcscmp(argv[1],L"--run")&&wcscmp(argv[1],L"--until-stop")))return 2;
 untilStop=!wcscmp(argv[1],L"--until-stop");
 shellPid=wcstoul(argv[2],NULL,10);ULONGLONG birth=_wcstoui64(argv[3],NULL,10);DWORD seconds=wcstoul(argv[5],NULL,10);if(seconds<15||seconds>3600||untilStop&&seconds>90)return 3;
 shellProcess=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,shellPid);wchar_t path[32768];DWORD n=32768;DWORD actual=0;GetWindowThreadProcessId(GetShellWindow(),&actual);if(!shellProcess||born(shellProcess)!=birth||!QueryFullProcessImageNameW(shellProcess,0,path,&n)||_wcsicmp(path,argv[4])||actual!=shellPid)return 4;
 wchar_t mutexName[128];swprintf(mutexName,128,L"Local\\Windows10NetworkTray_%lu_%llu",shellPid,birth);HANDLE mutex=CreateMutexW(NULL,TRUE,mutexName);if(!mutex||GetLastError()==ERROR_ALREADY_EXISTS)return 5;
 wcscpy(stopFile,argv[6]);FILE*f=_wfopen(argv[8],L"w");if(!f)return 6;setvbuf(f,NULL,_IONBF,0);networkTrace=f;hostDeadline=GetTickCount64()+seconds*1000;MSG msg;PeekMessageW(&msg,NULL,0,0,PM_NOREMOVE);doneEvent=CreateEventW(NULL,TRUE,FALSE,NULL);HANDLE watchdog=CreateThread(NULL,0,hostWatch,(void*)(ULONG_PTR)GetCurrentThreadId(),0,NULL);
 if(!doneEvent||!watchdog)return 8;
 HRESULT hr=CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);BOOL comInitialized=SUCCEEDED(hr);HMODULE dll=NULL;IUnknown*object=NULL;BOOL started=FALSE;
 if(SUCCEEDED(hr)){dll=LoadLibraryExW(argv[9],NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);if(!dll)hr=HRESULT_FROM_WIN32(GetLastError());}
 if(SUCCEEDED(hr)&&(!privateGuid()||!installPrivateNotify(dll)||!installNetworkReg(dll)))hr=E_UNEXPECTED;
 if(SUCCEEDED(hr)){typedef HRESULT(WINAPI*Factory)(REFCLSID,REFIID,void**);Factory get=(Factory)GetProcAddress(dll,"DllGetClassObject");IClassFactory*factory=NULL;hr=get?get(&CLSID_Network,&IID_IClassFactory,(void**)&factory):E_FAIL;if(SUCCEEDED(hr)&&factory){hr=IClassFactory_CreateInstance(factory,NULL,&IID_SSO,(void**)&object);IClassFactory_Release(factory);}else if(SUCCEEDED(hr))hr=E_UNEXPECTED;}
 if(SUCCEEDED(hr)&&object){void**v=*(void***)object;DWORD count=0;HANDLE*handles=NULL;typedef HRESULT(WINAPI*Start)(void*,DWORD,HANDLE**,DWORD*);if((BYTE*)v[3]!=(BYTE*)dll+0x3b00||(BYTE*)v[4]!=(BYTE*)dll+0x30050||(BYTE*)v[5]!=(BYTE*)dll+0xd2b0)hr=E_UNEXPECTED;else{hr=((Start)v[3])(object,0,&handles,&count);started=SUCCEEDED(hr);fprintf(f,"Start=%08lx handles=%p count=%lu (NOT visual proof)\n",hr,handles,count);if(count!=0||handles!=NULL)hr=E_UNEXPECTED;}}
 if(started&&object){DWORD initialized=*(DWORD*)((BYTE*)object+0x4c);HWND tray=*(HWND*)((BYTE*)object+0x58);DWORD windowPid=0;DWORD windowThread=tray?GetWindowThreadProcessId(tray,&windowPid):0;wchar_t className[256]={0};if(tray)GetClassNameW(tray,className,256);fprintf(f,"GenuinePNI initialized=%lu hwnd=%p ownerPid=%lu ownerThread=%lu class=%ls (genuine ADD required below)\n",initialized,tray,windowPid,windowThread,className);if(initialized!=1||!tray||windowPid!=GetCurrentProcessId())hr=E_FAIL;}
 if(SUCCEEDED(hr)&&!InterlockedCompareExchange(&realAddSucceeded,0,0))hr=E_FAIL;
 if(stopRequested&&SUCCEEDED(hr))hr=HRESULT_FROM_WIN32(ERROR_CANCELLED);
 fprintf(f,"Bootstrap=%08lx\n",hr);
 if(SUCCEEDED(hr)&&started){FILE*ready=_wfopen(argv[7],L"wx");if(!ready)hr=E_FAIL;else{fprintf(ready,"LifecycleReady; GenuineNotify ADD succeeded; visual placement unverified\n");fclose(ready);}}
 if(SUCCEEDED(hr)){InterlockedExchange(&bootstrapComplete,1);fprintf(f,"Running UntilStop=%d; bootstrap finished, no total-hour deadline in persistent mode\n",untilStop);for(;;){DWORD event=MsgWaitForMultipleObjects(0,NULL,FALSE,100,QS_ALLINPUT);(void)event;if(stopRequested||(!bootstrapComplete&&GetTickCount64()>hostDeadline)||(!untilStop&&GetTickCount64()>hostDeadline)||GetFileAttributesW(stopFile)!=INVALID_FILE_ATTRIBUTES)break;static ULONGLONG nextThemeTick=0;DWORD light=0;if(GetTickCount64()>=nextThemeTick&&(nextThemeTick=GetTickCount64()+500)&&lastGenuineValid&&readSystemLight(&light)&&(!themeKnown||light!=themeLight||highContrast()!=themeContrast)){NOTIFYICONDATAW refresh=lastGenuine;refresh.uFlags=NIF_GUID|NIF_ICON;privateNotify(NIM_MODIFY,&refresh);fprintf(f,"SystemTheme refreshed light=%lu\n",light);}
while(PeekMessageW(&msg,NULL,0,0,PM_REMOVE)){if(msg.message==WM_QUIT)goto cleanup;TranslateMessage(&msg);DispatchMessageW(&msg);}}}
 cleanup:
 if(started&&object){typedef HRESULT(WINAPI*Stop)(void*);HRESULT stop=((Stop)(*(void***)object)[4])(object);fprintf(f,"Stop=%08lx\n",stop);}
 if(lastGenuineValid&&lastGenuine.hIcon){DestroyIcon(lastGenuine.hIcon);lastGenuineValid=FALSE;}if(object)IUnknown_Release(object);if(dll)FreeLibrary(dll);if(comInitialized)CoUninitialize();fprintf(f,"Released own SSO; no Explorer termination\n");networkTrace=NULL;fclose(f);SetEvent(doneEvent);if(WaitForSingleObject(watchdog,2000)!=WAIT_OBJECT_0)ExitProcess(126);CloseHandle(watchdog);CloseHandle(doneEvent);CloseHandle(shellProcess);ReleaseMutex(mutex);CloseHandle(mutex);LocalFree(argv);return FAILED(hr)?7:0;
}
