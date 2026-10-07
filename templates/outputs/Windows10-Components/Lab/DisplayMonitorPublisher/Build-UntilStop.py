"""Separate staged lease executable; never replaces the working bounded publisher."""
from pathlib import Path
import hashlib,json,subprocess
lab=Path(__file__).resolve().parent;base=lab.parent.parent;root=base.parent.parent
source=(lab/'MonitorPublisher.c').read_text(encoding='utf-8-sig')
source_hash=hashlib.sha256((lab/'MonitorPublisher.c').read_bytes()).hexdigest()
start=source.index('typedef struct {HANDLE Ready;DWORD Milliseconds;} Watchdog;')
end=source.index('static void release',start)
replacement=r'''
static BOOL identity(HANDLE,DWORD,ULONGLONG,PCWSTR);
static ULONGLONG ftValue(const FILETIME*f){return ((ULONGLONG)f->dwHighDateTime<<32)|f->dwLowDateTime;}
typedef struct {HANDLE Ready,Done,Thread,Owner,Target;DWORD Milliseconds,TargetPid;ULONGLONG TargetBorn;PCWSTR TargetPath,CancelFile;volatile LONG Running;volatile LONG64 Pulse;} Watchdog;
static BOOL cancelled(PCWSTR p){return p&&p[0]&&GetFileAttributesW(p)!=INVALID_FILE_ATTRIBUTES;}
static DWORD WINAPI watchdog(void*arg){Watchdog*w=arg;ULONGLONG started=GetTickCount64(),cancelTick=0;SetEvent(w->Ready);
 for(;;){ULONGLONG now=GetTickCount64();BOOL stop=cancelled(w->CancelFile)||(w->Owner&&WaitForSingleObject(w->Owner,0)!=WAIT_TIMEOUT)||(w->Target&&!identity(w->Target,w->TargetPid,w->TargetBorn,w->TargetPath));
  if(stop&&!cancelTick)cancelTick=now;
  if((!w->Running&&now-started>w->Milliseconds)||(w->Running&&now-(ULONGLONG)InterlockedCompareExchange64(&w->Pulse,0,0)>15000)||(cancelTick&&now-cancelTick>10000))TerminateProcess(GetCurrentProcess(),0xdeca);
  if(WaitForSingleObject(w->Done,100)==WAIT_OBJECT_0)return 0;
 }
}
static BOOL startWatchdog(Watchdog*w,DWORD ms){w->Ready=CreateEventW(NULL,TRUE,FALSE,NULL);w->Done=CreateEventW(NULL,TRUE,FALSE,NULL);w->Milliseconds=ms;InterlockedExchange64(&w->Pulse,GetTickCount64());if(!w->Ready||!w->Done){if(w->Ready)CloseHandle(w->Ready);if(w->Done)CloseHandle(w->Done);return FALSE;}w->Thread=CreateThread(NULL,0,watchdog,w,0,NULL);if(!w->Thread){CloseHandle(w->Ready);CloseHandle(w->Done);return FALSE;}BOOL ready=WaitForSingleObject(w->Ready,5000)==WAIT_OBJECT_0;if(!ready){SetEvent(w->Done);if(WaitForSingleObject(w->Thread,5000)!=WAIT_OBJECT_0)TerminateProcess(GetCurrentProcess(),0xdeca);CloseHandle(w->Thread);CloseHandle(w->Ready);CloseHandle(w->Done);}return ready;}
static BOOL stopWatchdog(Watchdog*w){SetEvent(w->Done);BOOL joined=WaitForSingleObject(w->Thread,5000)==WAIT_OBJECT_0;if(!joined)TerminateProcess(GetCurrentProcess(),0xdeca);CloseHandle(w->Thread);CloseHandle(w->Done);CloseHandle(w->Ready);return joined;}
'''
source=source[:start]+replacement+source[end:]
source=source.replace('(*(ULONGLONG*)&b)==born','ftValue(&b)==born')
source=source.replace('Watchdog w;','Watchdog w={0};')
source=source.replace('static Monitor monitors[32];static UINT count;static BOOL failed;','static Monitor monitors[32];static UINT count;static BOOL failed;static BOOL quietInventory;')
source=source.replace('fwprintf(logFile,L"MONITOR id=', 'if(!quietInventory)fwprintf(logFile,L"MONITOR id=')
source=source.replace('fwprintf(logFile,L"APPBAR state=', 'if(!quietInventory)fwprintf(logFile,L"APPBAR state=')
source=source.replace('if(wcscmp(argv[1],L"--run")||argc!=7)return 68;',r'''if(!wcscmp(argv[1],L"--lease-proof")){Watchdog proof={0};if(!startWatchdog(&proof,1000))return 74;if(argc>3&&!wcscmp(argv[3],L"stall")){InterlockedExchange64(&proof.Pulse,GetTickCount64()-20000);InterlockedExchange(&proof.Running,1);}Sleep(INFINITE);return 75;}
 if(!wcscmp(argv[1],L"--lease-cleanup-proof")){Watchdog proof={0};if(!startWatchdog(&proof,2000))return 74;InterlockedExchange(&proof.Running,1);Sleep(100);if(!stopWatchdog(&proof))return 76;fwprintf(logFile,L"CLEANUP watchdog joined1\n");fclose(logFile);return 0;}
 if(wcscmp(argv[1],L"--until-stop")||argc!=10)return 68;''')
old='DWORD seconds=wcstoul(argv[6],NULL,10);if(!pid||!born||seconds<1||seconds>3600)return 69;'
new='DWORD seconds=wcstoul(argv[9],NULL,10);if(!pid||!born||seconds<5||seconds>90||!argv[6][0])return 69;'
assert old in source;source=source.replace(old,new)
old='Watchdog w={0};if(!startWatchdog(&w,(seconds+10)*1000))return 74;'
new=r'''Watchdog w={0};w.Target=target;w.TargetPid=pid;w.TargetBorn=born;w.TargetPath=argv[5];w.CancelFile=argv[6];
 DWORD ownerPid=wcstoul(argv[7],NULL,10);ULONGLONG ownerBorn=wcstoull(argv[8],NULL,10);FILETIME ob,oe,ok,ou;WCHAR ownerPath[32768],expectedOwner[32768];DWORD ownerLength=32768;
 w.Owner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,ownerPid);GetSystemDirectoryW(expectedOwner,32768);wcscat(expectedOwner,L"\\WindowsPowerShell\\v1.0\\powershell.exe");
 if(!w.Owner||!GetProcessTimes(w.Owner,&ob,&oe,&ok,&ou)||ftValue(&ob)!=ownerBorn||!QueryFullProcessImageNameW(w.Owner,0,ownerPath,&ownerLength)||_wcsicmp(ownerPath,expectedOwner)||cancelled(w.CancelFile))return 78;
 if(!startWatchdog(&w,seconds*1000))return 74;'''
assert old in source;source=source.replace(old,new)
source=source.replace('ULONGLONG deadline=GetTickCount64()+1000ULL*seconds;',r'''InterlockedExchange64(&w.Pulse,GetTickCount64());InterlockedExchange(&w.Running,1);
 fwprintf(logFile,L"UNTIL_STOP ready bootstrap=%lu stallBound=15 cleanupBound=10 ownerPid=%lu\n",seconds,ownerPid);fflush(logFile);quietInventory=TRUE;''')
source=source.replace('while(GetTickCount64()<deadline&&identity(target,pid,born,argv[5]))','while(!cancelled(w.CancelFile)&&WaitForSingleObject(w.Owner,0)==WAIT_TIMEOUT&&identity(target,pid,born,argv[5]))')
source=source.replace('if(FAILED(hr))break;\n }','if(FAILED(hr))break;InterlockedExchange64(&w.Pulse,GetTickCount64());\n }')
source=source.replace('clean(prior,oldCount);if(!same)',r'''BOOL changed=FALSE;for(UINT i=0;i<count&&!changed;i++)for(UINT j=0;j<oldCount;j++)if(monitors[i].MonitorId==prior[j].MonitorId){Monitor a=monitors[i],b=prior[j];a.PersistentDeviceId=NULL;b.PersistentDeviceId=NULL;if(memcmp(&a,&b,sizeof(a)))changed=TRUE;}
  if(changed){fwprintf(logFile,L"INVENTORY_CHANGED count=%u\n",count);for(UINT i=0;i<count;i++)fwprintf(logFile,L"CHANGE monitor=%llx scale=%f work=%f,%f,%f,%f\n",monitors[i].MonitorId,monitors[i].RawPixelsPerViewPixel,monitors[i].WorkArea.X,monitors[i].WorkArea.Y,monitors[i].WorkArea.Width,monitors[i].WorkArea.Height);fflush(logFile);}
  clean(prior,oldCount);if(!same)''')
source=source.replace('if(target)CloseHandle(target);CloseHandle(w.Ready);','stopWatchdog(&w);if(target)CloseHandle(target);if(w.Owner)CloseHandle(w.Owner);')
source=source.replace('HRESULT hr=initialize(RO_INIT_MULTITHREADED);if(FAILED(hr))return 71;','HRESULT hr=initialize(RO_INIT_MULTITHREADED);if(FAILED(hr)){stopWatchdog(&w);CloseHandle(target);CloseHandle(w.Owner);ReleaseMutex(exclusive);CloseHandle(exclusive);fclose(logFile);return 71;}')
(lab/'MonitorPublisherUntilStop.c').write_text(source,encoding='utf-8')
cmd=[str(root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'),'cc','-target','x86_64-windows-gnu','-municode','-mwindows','-Wl,--subsystem,windows','-Dwmain=BrokerExistingWmain',str(lab/'MonitorPublisherUntilStop.c'),str(base/'Lab/BrokerGuiEntry/BrokerGuiEntry.c'),'-o',str(lab/'MonitorPublisherUntilStop.exe'),'-luser32','-lshell32','-lole32']
p=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,text=True)
if p.returncode:raise RuntimeError(p.stderr)
assert hashlib.sha256((lab/'MonitorPublisher.c').read_bytes()).hexdigest()==source_hash
report=dict(CanonicalPublisherUnmodifiedSHA256=source_hash,Command=cmd,ExitCode=p.returncode,ActivationPerformed=False)
(lab/'untilstop-build-report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print('Separate GUI UntilStop publisher staged; stock server not activated')
