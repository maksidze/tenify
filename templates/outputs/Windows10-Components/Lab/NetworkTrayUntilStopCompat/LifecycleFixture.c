#define wWinMain FactoryProbeEntry
#include "../NetworkTrayCompat/NetworkFactoryProbe.c"
#undef wWinMain
static HANDLE shellProcess;
static DWORD shellPid;
static wchar_t stopFile[32768];
static HANDLE doneEvent;
static volatile LONG stopRequested;
static ULONGLONG hostDeadline;
static BOOL untilStop;
static volatile LONG bootstrapComplete;
static DWORD WINAPI hostWatch(void*x){ULONGLONG stopTick=0;for(;;){if(WaitForSingleObject(doneEvent,200)==WAIT_OBJECT_0)return 0;DWORD pid=0;GetWindowThreadProcessId(GetShellWindow(),&pid);BOOL stop=WaitForSingleObject(shellProcess,0)==WAIT_OBJECT_0||(!bootstrapComplete&&GetTickCount64()>hostDeadline)||(!untilStop&&GetTickCount64()>hostDeadline)||GetFileAttributesW(stopFile)!=INVALID_FILE_ATTRIBUTES;if(stop&&!stopTick){stopTick=GetTickCount64();InterlockedExchange(&stopRequested,1);PostThreadMessageW((DWORD)(ULONG_PTR)x,WM_QUIT,0,0);}if(stopTick&&GetTickCount64()>stopTick+500)ExitProcess(125);}return 0;}
static ULONGLONG born(HANDLE p){FILETIME a,b,c,d;if(!GetProcessTimes(p,&a,&b,&c,&d))return 0;return((ULONGLONG)a.dwHighDateTime<<32)|a.dwLowDateTime;}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE prev,LPWSTR line,int show){
 int argc;wchar_t**argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(argc==3){LocalFree(argv);return FactoryProbeEntry(h,prev,line,show);}if(argc!=10||(wcscmp(argv[1],L"--run")&&wcscmp(argv[1],L"--until-stop")))return 2;
 untilStop=!wcscmp(argv[1],L"--until-stop");
 shellPid=wcstoul(argv[2],NULL,10);ULONGLONG birth=_wcstoui64(argv[3],NULL,10);DWORD seconds=wcstoul(argv[5],NULL,10);if(seconds<1||seconds>3600||untilStop&&seconds>90)return 3;
 shellProcess=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,shellPid);wchar_t path[32768];DWORD n=32768;DWORD actual=0;GetWindowThreadProcessId(GetShellWindow(),&actual);if(!shellProcess||born(shellProcess)!=birth||!QueryFullProcessImageNameW(shellProcess,0,path,&n)||_wcsicmp(path,argv[4]))return 4;
 wchar_t mutexName[128];swprintf(mutexName,128,L"Local\\Windows10NetworkTray_%lu_%llu",shellPid,birth);HANDLE mutex=CreateMutexW(NULL,TRUE,mutexName);if(!mutex||GetLastError()==ERROR_ALREADY_EXISTS)return 5;
 wcscpy(stopFile,argv[6]);FILE*f=_wfopen(argv[8],L"w");if(!f)return 6;setvbuf(f,NULL,_IONBF,0);hostDeadline=GetTickCount64()+seconds*1000;MSG msg;PeekMessageW(&msg,NULL,0,0,PM_NOREMOVE);doneEvent=CreateEventW(NULL,TRUE,FALSE,NULL);HANDLE watchdog=CreateThread(NULL,0,hostWatch,(void*)(ULONG_PTR)GetCurrentThreadId(),0,NULL);
 if(!doneEvent||!watchdog)return 8;
 HRESULT hr=S_OK;BOOL comInitialized=FALSE;HMODULE dll=NULL;IUnknown*object=NULL;BOOL started=FALSE;if(!wcscmp(argv[9],L"stall"))Sleep(INFINITE);
 if(stopRequested&&SUCCEEDED(hr))hr=HRESULT_FROM_WIN32(ERROR_CANCELLED);
 fprintf(f,"Bootstrap=%08lx\n",hr);
 if(SUCCEEDED(hr)){FILE*ready=_wfopen(argv[7],L"wx");if(!ready)hr=E_FAIL;else{fprintf(ready,"LifecycleReady; visual icon unverified\n");fclose(ready);}}
 if(SUCCEEDED(hr)){InterlockedExchange(&bootstrapComplete,1);fprintf(f,"Running UntilStop=%d; bootstrap finished, no total-hour deadline in persistent mode\n",untilStop);for(;;){DWORD event=MsgWaitForMultipleObjects(0,NULL,FALSE,100,QS_ALLINPUT);(void)event;if(stopRequested||(!bootstrapComplete&&GetTickCount64()>hostDeadline)||(!untilStop&&GetTickCount64()>hostDeadline)||GetFileAttributesW(stopFile)!=INVALID_FILE_ATTRIBUTES)break;while(PeekMessageW(&msg,NULL,0,0,PM_REMOVE)){if(msg.message==WM_QUIT)goto cleanup;TranslateMessage(&msg);DispatchMessageW(&msg);}}}
 cleanup:
 fprintf(f,"FIXTURE cooperative cleanup; no actual SSO was started\n");
 if(started&&object){typedef HRESULT(WINAPI*Stop)(void*);HRESULT stop=((Stop)(*(void***)object)[4])(object);fprintf(f,"Stop=%08lx\n",stop);}
 if(object)IUnknown_Release(object);if(dll)FreeLibrary(dll);if(comInitialized)CoUninitialize();fprintf(f,"Released own SSO; no Explorer termination\n");fclose(f);SetEvent(doneEvent);if(WaitForSingleObject(watchdog,2000)!=WAIT_OBJECT_0)ExitProcess(126);CloseHandle(watchdog);CloseHandle(doneEvent);CloseHandle(shellProcess);ReleaseMutex(mutex);CloseHandle(mutex);LocalFree(argv);return FAILED(hr)?7:0;
}
