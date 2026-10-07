#ifndef UNICODE
#define UNICODE
#endif
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
#include <sddl.h>
#include <tlhelp32.h>
#include "StartCompatTrace.h"
#include "SessionLifetime.h"
#include <io.h>

static ULONGLONG sessionFileTimeValue(const FILETIME*f){return ((ULONGLONG)f->dwHighDateTime<<32)|f->dwLowDateTime;}
static wchar_t sessionCancel[32768];
static HANDLE sessionOwner;
static BOOL sessionUntilStop;
static ULONGLONG sessionExpectedBirth;
static BOOL sessionCancelled(void){return (sessionCancel[0]&&GetFileAttributesW(sessionCancel)!=INVALID_FILE_ATTRIBUTES)||(sessionOwner&&WaitForSingleObject(sessionOwner,0)!=WAIT_TIMEOUT);}
static FILE *logFile;
static DWORD childPid;
static BOOL detachAfterBootstrap;
static wchar_t expectedPackage[4096];
static BOOL readChild(HANDLE process,const void *address,void *out,SIZE_T size){SIZE_T read=0;return ReadProcessMemory(process,address,out,size,&read)&&read==size;}
static unsigned patchChildImports(HANDLE process,BYTE *base,BYTE *remoteProxy,const wchar_t *proxyPath){
 IMAGE_DOS_HEADER dos;IMAGE_NT_HEADERS64 nt;if(!readChild(process,base,&dos,sizeof(dos))||dos.e_magic!=IMAGE_DOS_SIGNATURE||!readChild(process,base+dos.e_lfanew,&nt,sizeof(nt)))return 0;
 HMODULE local=LoadLibraryExW(proxyPath,NULL,DONT_RESOLVE_DLL_REFERENCES);if(!local)return 0;
 unsigned changed=0;DWORD rva=nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
 for(unsigned n=0;n<1024;n++){
  IMAGE_IMPORT_DESCRIPTOR d;if(!readChild(process,base+rva+n*sizeof(d),&d,sizeof(d))||!d.Name)break;
  char module[256]={0};readChild(process,base+d.Name,module,255);if(_stricmp(module,"wincorlib.dll"))continue;
  for(unsigned i=0;i<4096;i++){
   ULONGLONG thunk;if(!readChild(process,base+d.OriginalFirstThunk+i*8,&thunk,8)||!thunk)break;if(thunk&IMAGE_ORDINAL_FLAG64)continue;
   char symbol[512]={0};readChild(process,base+thunk+2,symbol,511);
   const char *hook=!strcmp(symbol,"?GetActivationFactoryByPCWSTR@@YAJPEAXAEAVGuid@Platform@@PEAPEAX@Z")?"StartCompatGetFactory":!strcmp(symbol,"?GetCmdArguments@Details@Platform@@YAPEAPEA_WPEAH@Z")?"StartCompatGetArguments":NULL;
   if(!hook)continue;FARPROC localHook=GetProcAddress(local,hook);if(!localHook)continue;
   void *target=remoteProxy+((BYTE*)localHook-(BYTE*)local),*address=base+d.FirstThunk+i*8;DWORD old=0,unused=0;SIZE_T wrote=0;
   if(VirtualProtectEx(process,address,8,PAGE_READWRITE,&old)){if(WriteProcessMemory(process,address,&target,8,&wrote)&&wrote==8)changed++;VirtualProtectEx(process,address,8,old,&unused);}
  }
 }
 FreeLibrary(local);return changed;
}
static void logline(const char *format,...){if(ftell(logFile)>8*1024*1024){fflush(logFile);_chsize(_fileno(logFile),0);fseek(logFile,0,SEEK_SET);fputs("LOG rolled; bounded8MiB\n",logFile);}va_list args;va_start(args,format);vfprintf(logFile,format,args);va_end(args);fputc('\n',logFile);fflush(logFile);}
static void exceptionDetails(HANDLE process,const EXCEPTION_RECORD *record){
 for(DWORD i=0;i<record->NumberParameters&&i<EXCEPTION_MAXIMUM_PARAMETERS;i++)logline("EXCEPTION_PARAM %lu=%llx",i,(ULONGLONG)record->ExceptionInformation[i]);
 if(record->ExceptionCode==0x40080201&&record->NumberParameters>=3){SIZE_T length=(SIZE_T)record->ExceptionInformation[1];if(length<2048){wchar_t message[2048]={0};if(readChild(process,(void*)record->ExceptionInformation[2],message,length*sizeof(wchar_t)))logline("WINRT_MESSAGE %ls",message);}}
 if(record->ExceptionCode!=0xc000027b||record->NumberParameters<2)return;
 ULONG_PTR count=record->ExceptionInformation[1];if(count>16)count=16;
 for(ULONG_PTR n=0;n<count;n++){
  ULONGLONG address=0;BYTE raw[56]={0};if(!readChild(process,(void*)(record->ExceptionInformation[0]+8*n),&address,8)||!readChild(process,(void*)address,raw,sizeof(raw)))continue;
  DWORD size=*(DWORD*)raw,signature=*(DWORD*)(raw+4),flags=*(DWORD*)(raw+12);LONG hr=*(LONG*)(raw+8);
  logline("STOWED %llu ptr=%llx size=%lu signature=%08lx HRESULT=%08lx form=%lu tid=%lu",(ULONGLONG)n,address,size,signature,hr,flags&3,flags>>2);
  if((flags&3)==1){DWORD word=*(DWORD*)(raw+24),words=*(DWORD*)(raw+28);ULONGLONG trace=*(ULONGLONG*)(raw+32);logline("STOWED address=%llx wordSize=%lu words=%lu trace=%llx",*(ULONGLONG*)(raw+16),word,words,trace);if(word==8){if(words>160)words=160;ULONGLONG stack[160]={0};if(readChild(process,(void*)trace,stack,words*8))for(DWORD i=0;i<words;i++)logline("STOWED_STACK %lu=%llx",i,stack[i]);}}
  else if((flags&3)==2){wchar_t message[2048]={0};SIZE_T got=0;ReadProcessMemory(process,(void*)*(ULONGLONG*)(raw+16),message,sizeof(message)-2,&got);message[2047]=0;logline("STOWED_MESSAGE %ls",message);}
 }
}
static BOOL CALLBACK windowInfo(HWND w,LPARAM p){(void)p;DWORD pid=0;GetWindowThreadProcessId(w,&pid);if(pid==childPid){wchar_t name[256],title[512];GetClassNameW(w,name,256);GetWindowTextW(w,title,512);logline("WINDOW hwnd=%p class=%ls title=%ls visible=%d",w,name,title,IsWindowVisible(w));}return TRUE;}
static void childWindows(void){EnumWindows(windowInfo,0);HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);if(snap==INVALID_HANDLE_VALUE)return;THREADENTRY32 row={sizeof(row)};if(Thread32First(snap,&row))do{if(row.th32OwnerProcessID==childPid)EnumThreadWindows(row.th32ThreadID,windowInfo,0);}while(Thread32Next(snap,&row));CloseHandle(snap);}
static void describeProcess(HANDLE process){ HANDLE token=NULL;if(OpenProcessToken(process,TOKEN_QUERY,&token)){DWORD container=0,bytes=0;GetTokenInformation(token,TokenIsAppContainer,&container,sizeof(container),&bytes);BYTE sidInfo[1024]={0};if(GetTokenInformation(token,TokenAppContainerSid,sidInfo,sizeof(sidInfo),&bytes)){wchar_t *sidText=NULL;PSID sid=*(PSID*)sidInfo;if(sid&&ConvertSidToStringSidW(sid,&sidText)){logline("TOKEN appContainer=%lu SID=%ls",container,sidText);LocalFree(sidText);}else logline("TOKEN appContainer=%lu",container);}CloseHandle(token);}DWORD signaturePolicy=0;GetProcessMitigationPolicy(process,ProcessSignaturePolicy,&signaturePolicy,sizeof(signaturePolicy));logline("MITIGATION signaturePolicy=%08lx",signaturePolicy);}
int wmain(int argc,wchar_t **argv){
 if(argc==4&&!wcscmp(argv[1],L"--windows")){logFile=_wfopen(argv[2],L"wb");if(!logFile)return 69;childPid=wcstoul(argv[3],NULL,10);HDESK input=OpenInputDesktop(0,FALSE,DESKTOP_READOBJECTS|DESKTOP_ENUMERATE);if(input){SetThreadDesktop(input);childWindows();CloseDesktop(input);}fclose(logFile);return 0;}

 if(argc==4&&!wcscmp(argv[1],L"--policy")){logFile=_wfopen(argv[2],L"wb");if(!logFile)return 69;HANDLE process=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,wcstoul(argv[3],NULL,10));if(process){describeProcess(process);CloseHandle(process);}else logline("OpenProcess error=%lu",GetLastError());fclose(logFile);return 0;}
 BOOL expandedInternal=argc==12&&expectedPackage[0]&&!wcscmp(argv[7],L"--attach");BOOL brokerAttach=FALSE;if(!expandedInternal)for(int i=1;i+1<argc;i++)if(!wcscmp(argv[i],L"-p"))brokerAttach=TRUE;
 if(brokerAttach){
  wchar_t config[32768],values[6][32768];GetModuleFileNameW(NULL,config,32768);wchar_t *slash=wcsrchr(config,L'\\');if(!slash)return 67;wcscpy(slash+1,L"BrokerStartCompat.ini");
  for(int i=1;i+1<argc;i++)if(!wcscmp(argv[i],L"--config")){if(wcschr(argv[i+1],L':'))wcsncpy(config,argv[i+1],32767);else wcscpy(slash+1,argv[i+1]);}
  GetPrivateProfileStringW(L"Debugger",L"CancelFile",L"",sessionCancel,32768,config);
  sessionUntilStop=GetPrivateProfileIntW(L"Debugger",L"UntilStop",0,config)!=0;
  wchar_t expectedBirth[32];GetPrivateProfileStringW(L"Debugger",L"TargetBirth",L"",expectedBirth,32,config);sessionExpectedBirth=wcstoull(expectedBirth,NULL,10);
  wchar_t ownerBirthText[32],ownerPath[32768],actualOwnerPath[32768];GetPrivateProfileStringW(L"Debugger",L"OwnerBirth",L"",ownerBirthText,32,config);GetPrivateProfileStringW(L"Debugger",L"OwnerPath",L"",ownerPath,32768,config);
  DWORD ownerPid=GetPrivateProfileIntW(L"Debugger",L"OwnerPid",0,config),ownerSize=32768;FILETIME ob,oe,ok,ou;
  sessionOwner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,ownerPid);
  if(!sessionOwner||!GetProcessTimes(sessionOwner,&ob,&oe,&ok,&ou)||sessionFileTimeValue(&ob)!=wcstoull(ownerBirthText,NULL,10)||!QueryFullProcessImageNameW(sessionOwner,0,actualOwnerPath,&ownerSize)||_wcsicmp(actualOwnerPath,ownerPath)){if(sessionOwner)CloseHandle(sessionOwner);sessionOwner=NULL;return 71;}

  detachAfterBootstrap=GetPrivateProfileIntW(L"Debugger",L"DetachAfterBootstrap",0,config)!=0;
  const wchar_t *keys[]={L"Report",L"Target",L"Seconds",L"ServerArgument",L"Proxy",L"DeadlineFileTime"};for(int i=0;i<6;i++)GetPrivateProfileStringW(L"Debugger",keys[i],L"",values[i],32768,config);
  GetPrivateProfileStringW(L"Debugger",L"PackageFullName",L"",expectedPackage,4096,config);FILETIME ft;GetSystemTimeAsFileTime(&ft);ULONGLONG deadline=wcstoull(values[5],NULL,10);DWORD pid=0,tid=0;for(int i=1;i+1<argc;i++){if(!wcscmp(argv[i],L"-p"))pid=wcstoul(argv[i+1],NULL,10);if(!wcscmp(argv[i],L"-tid"))tid=wcstoul(argv[i+1],NULL,10);}
  if(!pid||!tid||!values[0][0]||!values[1][0]||!expectedPackage[0]||deadline<sessionFileTimeValue(&ft)){HANDLE t=OpenThread(THREAD_SUSPEND_RESUME|THREAD_QUERY_INFORMATION,FALSE,tid);if(t){if(GetProcessIdOfThread(t)==pid)ResumeThread(t);CloseHandle(t);}return 68;}
  HANDLE candidate=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);wchar_t observed[32768]={0};DWORD observedLength=32768;BOOL correct=candidate&&QueryFullProcessImageNameW(candidate,0,observed,&observedLength)&&!_wcsicmp(observed,values[1]);if(candidate)CloseHandle(candidate);
  wchar_t claim[32768];swprintf(claim,32768,L"%ls.claim",values[0]);HANDLE claimFile=correct?CreateFileW(claim,GENERIC_WRITE,0,NULL,CREATE_NEW,0,NULL):INVALID_HANDLE_VALUE;
  if(!correct||claimFile==INVALID_HANDLE_VALUE){HANDLE t=OpenThread(THREAD_SUSPEND_RESUME|THREAD_QUERY_INFORMATION,FALSE,tid);if(t){if(GetProcessIdOfThread(t)==pid)ResumeThread(t);CloseHandle(t);}return 0;}DWORD written=0;WriteFile(claimFile,&pid,sizeof(pid),&written,NULL);CloseHandle(claimFile);
  wchar_t pidText[20],tidText[20];swprintf(pidText,20,L"%lu",pid);swprintf(tidText,20,L"%lu",tid);wchar_t *expanded[]={argv[0],values[0],values[1],values[2],values[3],L"--live",values[4],L"--attach",L"-p",pidText,L"-tid",tidText};return wmain(12,expanded);
 }
 for(int i=1;i<argc;i++)if(!wcscmp(argv[i],L"--detach"))detachAfterBootstrap=TRUE;
 if(argc<3)return 64;logFile=_wfopen(argv[1],L"wb");if(!logFile)return 65;
 SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
 wchar_t deskName[128],deskPath[160],command[32768];swprintf(deskName,128,L"StartCompatTest_%lu",GetCurrentProcessId());swprintf(deskPath,160,L"WinSta0\\%ls",deskName);
 BOOL live=(argc>5&&!wcscmp(argv[5],L"--live"));HDESK desk=live?OpenInputDesktop(0,FALSE,DESKTOP_READOBJECTS|DESKTOP_ENUMERATE):CreateDesktopW(deskName,NULL,NULL,0,GENERIC_ALL,NULL);logline("ObserverDesktop=%p live=%d error=%lu",desk,live,GetLastError());if(!desk)return 1;if(live){BOOL assigned=SetThreadDesktop(desk);wchar_t desktopName[256]={0};GetUserObjectInformationW(GetThreadDesktop(GetCurrentThreadId()),UOI_NAME,desktopName,sizeof(desktopName),NULL);logline("ObserverDesktop assigned=%d name=%ls",assigned,desktopName);}
 const wchar_t *injectPath=argc>6?argv[6]:NULL;HANDLE injectThread=NULL;DWORD injectTid=0;BYTE *imageBase=NULL,*proxyBase=NULL,*entryAddress=NULL,entryByte=0;BOOL waitingEntry=FALSE;
 DWORD attachPid=0,attachTid=0;for(int i=7;i+1<argc;i++){if(!wcscmp(argv[i],L"-p"))attachPid=wcstoul(argv[i+1],NULL,10);if(!wcscmp(argv[i],L"-tid"))attachTid=wcstoul(argv[i+1],NULL,10);}BOOL attached=attachPid&&attachTid;
 swprintf(command,32768,L"\"%ls\"%ls%ls",argv[2],argc>4?L" ":L"",argc>4?argv[4]:L"");STARTUPINFOW si={0};si.cb=sizeof(si);si.lpDesktop=live?NULL:deskPath;PROCESS_INFORMATION pi={0};
 BOOL created=FALSE;
 if(attached){pi.dwProcessId=attachPid;pi.dwThreadId=attachTid;pi.hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,attachPid);pi.hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,attachTid);wchar_t observed[32768]={0};DWORD n=32768;FILETIME born,exit,kernel,user,now;GetSystemTimeAsFileTime(&now);BOOL fresh=pi.hProcess&&GetProcessTimes(pi.hProcess,&born,&exit,&kernel,&user)&&(sessionFileTimeValue(&now)-sessionFileTimeValue(&born)<300000000ULL);BOOL exact=pi.hProcess&&sessionExpectedBirth&&sessionFileTimeValue(&born)==sessionExpectedBirth&&QueryFullProcessImageNameW(pi.hProcess,0,observed,&n)&&!_wcsicmp(observed,argv[2]);BOOL thread=pi.hThread&&GetProcessIdOfThread(pi.hThread)==attachPid;wchar_t package[4096]={0};UINT pn=4096;typedef LONG(WINAPI *PKGFULL)(HANDLE,UINT*,wchar_t*);PKGFULL getFull=(PKGFULL)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"GetPackageFullName");LONG packageResult=getFull?getFull(pi.hProcess,&pn,package):ERROR_PROC_NOT_FOUND;BOOL packageMatches=packageResult==0&&expectedPackage[0]&&!wcscmp(package,expectedPackage);logline("ATTACH preflight fresh=%d exactPath=%d threadOwner=%d packageMatch=%d path=%ls package=%ls",fresh,exact,thread,packageMatches,observed,package);if(fresh&&exact&&thread&&packageMatches)created=DebugActiveProcess(attachPid);logline("AttachProcess=%d error=%lu pid=%lu",created,GetLastError(),attachPid);
 }else{created=CreateProcessW(argv[2],command,NULL,NULL,FALSE,DEBUG_ONLY_THIS_PROCESS,NULL,NULL,&si,&pi);logline("CreateProcess=%d error=%lu pid=%lu",created,GetLastError(),pi.dwProcessId);}
 if(!created){if(attached&&pi.hThread)ResumeThread(pi.hThread);if(pi.hThread)CloseHandle(pi.hThread);if(pi.hProcess)CloseHandle(pi.hProcess);CloseDesktop(desk);fclose(logFile);return 2;}
 describeProcess(pi.hProcess);
 childPid=pi.dwProcessId;typedef LONG(WINAPI *PFN_PACKAGE)(HANDLE,UINT*,wchar_t*);PFN_PACKAGE getPackage=(PFN_PACKAGE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"GetPackageFullName");if(getPackage){UINT n=4096;wchar_t package[4096]={0};LONG hr=getPackage(pi.hProcess,&n,package);logline("ChildPackage error=%ld value=%ls",hr,package);n=4096;hr=getPackage(GetCurrentProcess(),&n,package);logline("ParentPackage error=%ld value=%ls",hr,package);}DebugSetProcessKillOnExit(FALSE);DWORD seconds=argc>3?(DWORD)_wtoi(argv[3]):12;ULONGLONG deadline=GetTickCount64()+seconds*1000,drain=0;BOOL alive=TRUE,initial=TRUE,stopping=FALSE,detachRequested=FALSE,detached=FALSE;BYTE *remoteTrace=NULL;LONG lastTrace=0;BOOL modulesLogged=FALSE;
 SESSION_LIFETIME lifetime={0};if(!sessionOwner||!sessionLifetimeStart(&lifetime,pi.hProcess,sessionOwner,sessionCancel,seconds,sessionUntilStop)){TerminateProcess(pi.hProcess,0xdecd);DebugActiveProcessStop(childPid);ExitProcess(0xdecd);}
 ULONGLONG nextSnapshot=GetTickCount64()+5000;
 while(alive){
  if(GetTickCount64()>nextSnapshot){if(live)childWindows();else EnumDesktopWindows(desk,windowInfo,0);nextSnapshot=GetTickCount64()+5000;}
  if(!stopping && (sessionCancelled()||GetTickCount64()>deadline)){if(live)childWindows();else EnumDesktopWindows(desk,windowInfo,0);logline("TIMEOUT terminate OWN child pid=%lu",childPid);TerminateProcess(pi.hProcess,0xdec0);stopping=TRUE;drain=GetTickCount64()+3000;}
  if(stopping && GetTickCount64()>drain){DebugActiveProcessStop(childPid);break;}
  if(detached){
   if(remoteTrace){static START_TRACE_STATE state;if(readChild(pi.hProcess,remoteTrace,&state,sizeof(state))){LONG newest=state.nextSequence;if(newest-lastTrace>START_TRACE_COUNT){logline("TRACE_DROPPED count=%ld",newest-lastTrace-START_TRACE_COUNT);lastTrace=newest-START_TRACE_COUNT;}for(LONG seq=lastTrace+1;seq<=newest;seq++){START_TRACE_ENTRY *entry=&state.entries[(unsigned)(seq-1)%START_TRACE_COUNT];if(entry->sequence!=seq)break;entry->text[START_TRACE_CHARS-1]=0;logline("TRACE %ls",entry->text);lastTrace=seq;}}}
   if(!modulesLogged&&GetTickCount64()+4000>nextSnapshot){HANDLE modules=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,childPid);if(modules!=INVALID_HANDLE_VALUE){MODULEENTRY32W m={sizeof(m)};if(Module32FirstW(modules,&m))do{if(wcsstr(m.szModule,L"StartUI")||wcsstr(m.szModule,L"StartDocked")||wcsstr(m.szModule,L"wincorlib"))logline("MODULE base=%p path=%ls",m.modBaseAddr,m.szExePath);if(wcsstr(m.szModule,L"StartUI"))modulesLogged=TRUE;}while(Module32NextW(modules,&m));CloseHandle(modules);}}
   if(WaitForSingleObject(pi.hProcess,100)==WAIT_OBJECT_0){DWORD code=0;GetExitCodeProcess(pi.hProcess,&code);logline("EXIT detached code=%08lx",code);alive=FALSE;}continue;
  }
  DEBUG_EVENT e={0};if(!WaitForDebugEventEx(&e,100))continue;DWORD disposition=DBG_CONTINUE;
  if(e.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){imageBase=e.u.CreateProcessInfo.lpBaseOfImage;logline("CREATE_IMAGE base=%p",imageBase);if(e.u.CreateProcessInfo.hFile)CloseHandle(e.u.CreateProcessInfo.hFile);}
  else if(e.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT){wchar_t path[32768]={0};if(e.u.LoadDll.hFile){GetFinalPathNameByHandleW(e.u.LoadDll.hFile,path,32768,0);CloseHandle(e.u.LoadDll.hFile);}logline("DLL base=%p path=%ls",e.u.LoadDll.lpBaseOfDll,path);const wchar_t *clean=!wcsncmp(path,L"\\\\?\\",4)?path+4:path;if(injectPath&&!_wcsicmp(clean,injectPath))proxyBase=e.u.LoadDll.lpBaseOfDll;}
  else if(e.dwDebugEventCode==OUTPUT_DEBUG_STRING_EVENT){
   DWORD count=e.u.DebugString.nDebugStringLength;if(count>16383)count=16383;SIZE_T bytes=0;
   if(e.u.DebugString.fUnicode){wchar_t text[16384]={0};ReadProcessMemory(pi.hProcess,e.u.DebugString.lpDebugStringData,text,count*sizeof(wchar_t),&bytes);text[16383]=0;logline("DEBUG %ls",text);}
   else{char text[16384]={0};ReadProcessMemory(pi.hProcess,e.u.DebugString.lpDebugStringData,text,count,&bytes);text[16383]=0;logline("DEBUG %s",text);}
  }
  else if(e.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){DWORD code=e.u.Exception.ExceptionRecord.ExceptionCode;logline("EXCEPTION code=%08lx first=%lu address=%p",code,e.u.Exception.dwFirstChance,e.u.Exception.ExceptionRecord.ExceptionAddress);if(code!=EXCEPTION_BREAKPOINT)exceptionDetails(pi.hProcess,&e.u.Exception.ExceptionRecord);if(code==EXCEPTION_ACCESS_VIOLATION||code==0xc0000409||code==0xc000027b||code==0x40080201){HANDLE thread=OpenThread(THREAD_GET_CONTEXT,FALSE,e.dwThreadId);CONTEXT c={0};c.ContextFlags=CONTEXT_FULL;if(thread&&GetThreadContext(thread,&c)){logline("CONTEXT tid=%lu RIP=%llx RAX=%llx RBX=%llx RCX=%llx RDX=%llx RSI=%llx RDI=%llx R8=%llx R9=%llx RSP=%llx operation=%llu target=%llx",e.dwThreadId,c.Rip,c.Rax,c.Rbx,c.Rcx,c.Rdx,c.Rsi,c.Rdi,c.R8,c.R9,c.Rsp,(ULONGLONG)e.u.Exception.ExceptionRecord.ExceptionInformation[0],(ULONGLONG)e.u.Exception.ExceptionRecord.ExceptionInformation[1]);ULONGLONG stack[384]={0};if(readChild(pi.hProcess,(void*)c.Rsp,stack,sizeof(stack)))for(unsigned i=0;i<384;i++)logline("STACK +%x=%llx",i*8,stack[i]);}if(thread)CloseHandle(thread);}if(code==EXCEPTION_BREAKPOINT&&initial){initial=FALSE;
   if(injectPath){IMAGE_DOS_HEADER dos;IMAGE_NT_HEADERS64 nt;SIZE_T wrote=0;BYTE breakpoint=0xcc;DWORD old=0,unused=0;
    if(readChild(pi.hProcess,imageBase,&dos,sizeof(dos))&&readChild(pi.hProcess,imageBase+dos.e_lfanew,&nt,sizeof(nt))){entryAddress=imageBase+nt.OptionalHeader.AddressOfEntryPoint;readChild(pi.hProcess,entryAddress,&entryByte,1);if(VirtualProtectEx(pi.hProcess,entryAddress,1,PAGE_EXECUTE_READWRITE,&old)){waitingEntry=WriteProcessMemory(pi.hProcess,entryAddress,&breakpoint,1,&wrote);VirtualProtectEx(pi.hProcess,entryAddress,1,old,&unused);FlushInstructionCache(pi.hProcess,entryAddress,1);}}
    logline("INJECT entryBreakpoint=%p installed=%d",entryAddress,waitingEntry);if(!waitingEntry){TerminateProcess(pi.hProcess,0xdec3);stopping=TRUE;drain=GetTickCount64()+3000;}else if(attached){logline("ATTACH resume initial suspended thread=%lu result=%lu",attachTid,ResumeThread(pi.hThread));}
   }
  }else if(code==EXCEPTION_BREAKPOINT&&waitingEntry&&e.u.Exception.ExceptionRecord.ExceptionAddress==entryAddress){waitingEntry=FALSE;SIZE_T wrote=0;DWORD old=0,unused=0;VirtualProtectEx(pi.hProcess,entryAddress,1,PAGE_EXECUTE_READWRITE,&old);WriteProcessMemory(pi.hProcess,entryAddress,&entryByte,1,&wrote);VirtualProtectEx(pi.hProcess,entryAddress,1,old,&unused);FlushInstructionCache(pi.hProcess,entryAddress,1);CONTEXT context={0};context.ContextFlags=CONTEXT_CONTROL;GetThreadContext(pi.hThread,&context);context.Rip=(DWORD64)entryAddress;SetThreadContext(pi.hThread,&context);
   if(injectPath){SIZE_T bytes=(wcslen(injectPath)+1)*sizeof(wchar_t);void *remote=VirtualAllocEx(pi.hProcess,NULL,bytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);DWORD suspended=SuspendThread(pi.hThread);
    if(remote&&suspended!=(DWORD)-1&&WriteProcessMemory(pi.hProcess,remote,injectPath,bytes,&wrote))injectThread=CreateRemoteThread(pi.hProcess,NULL,0,(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryW"),remote,0,&injectTid);
    logline("INJECT loaderThread=%lu handle=%p error=%lu mainSuspended=%lu",injectTid,injectThread,GetLastError(),suspended);
    if(!injectThread){TerminateProcess(pi.hProcess,0xdec1);stopping=TRUE;drain=GetTickCount64()+3000;}
   }
  }else disposition=DBG_EXCEPTION_NOT_HANDLED;}
  else if(e.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){logline("EXIT code=%08lx",e.u.ExitProcess.dwExitCode);alive=FALSE;}
  else if(e.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT){/* Debug-event handle is Windows-owned; Continue(EXIT_THREAD) or detach closes it. */}
  else if(e.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT&&injectThread&&e.dwThreadId==injectTid){typedef LONG(WINAPI *QUERYTHREAD)(HANDLE,ULONG,void*,ULONG,ULONG*);QUERYTHREAD query=(QUERYTHREAD)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationThread");BYTE basic[64]={0};DWORD remoteError=0;if(query&&query(injectThread,0,basic,48,NULL)>=0){BYTE *teb=*(BYTE**)(basic+8);readChild(pi.hProcess,teb+0x68,&remoteError,sizeof(remoteError));}unsigned changed=proxyBase?patchChildImports(pi.hProcess,imageBase,proxyBase,injectPath):0;logline("INJECT loaded=%p exit=%08lx remoteLastError=%lu patchedHostImports=%u",proxyBase,e.u.ExitThread.dwExitCode,remoteError,changed);if(changed==2){ResumeThread(pi.hThread);if(detachAfterBootstrap)detachRequested=TRUE;}else{TerminateProcess(pi.hProcess,0xdec2);stopping=TRUE;drain=GetTickCount64()+3000;}CloseHandle(injectThread);injectThread=NULL;}
  if(!ContinueDebugEvent(e.dwProcessId,e.dwThreadId,disposition)){logline("EVENT_CONTINUE_FAILED code=%lu tid=%lu error=%lu",e.dwDebugEventCode,e.dwThreadId,GetLastError());TerminateProcess(pi.hProcess,0xdecb);stopping=TRUE;drain=GetTickCount64()+3000;detachRequested=FALSE;}
  if(detachRequested){detachRequested=FALSE;HMODULE local=LoadLibraryExW(injectPath,NULL,DONT_RESOLVE_DLL_REFERENCES);if(local){FARPROC state=GetProcAddress(local,"StartCompatTraceState");if(state)remoteTrace=proxyBase+((BYTE*)state-(BYTE*)local);FreeLibrary(local);}detached=DebugActiveProcessStop(childPid);BOOL stillDebugged=TRUE;if(!CheckRemoteDebuggerPresent(pi.hProcess,&stillDebugged))stillDebugged=TRUE;logline("DETACH afterBootstrap success=%d remoteDebugger=%d trace=%p",detached,stillDebugged,remoteTrace);if(detached&&!stillDebugged){wchar_t readyPath[32768];swprintf(readyPath,32768,L"%ls.ready",argv[1]);HANDLE f=CreateFileW(readyPath,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,0,NULL);DWORD written=0;const char ok[]="Detached=1\nRemoteDebugger=0\n";BOOL marked=f!=INVALID_HANDLE_VALUE&&WriteFile(f,ok,sizeof(ok)-1,&written,NULL)&&written==sizeof(ok)-1&&FlushFileBuffers(f);if(f!=INVALID_HANDLE_VALUE)CloseHandle(f);if(!marked){TerminateProcess(pi.hProcess,0xdecc);stopping=TRUE;drain=GetTickCount64()+3000;}else{sessionLifetimeReady(&lifetime);if(sessionUntilStop)deadline=~0ULL;logline("SESSION ready untilStop=%d; bounded bootstrap complete, owner/cancel lifetime",sessionUntilStop);}}if(!detached||stillDebugged){TerminateProcess(pi.hProcess,0xdec4);stopping=TRUE;drain=GetTickCount64()+3000;}}

 }
 if(!stopping){if(live)childWindows();else EnumDesktopWindows(desk,windowInfo,0);}
 if(!sessionLifetimeStop(&lifetime))ExitProcess(0xdecf);if(injectThread)CloseHandle(injectThread);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);if(sessionOwner){CloseHandle(sessionOwner);sessionOwner=NULL;}CloseDesktop(desk);logline("COMPLETE debugger controlled only its own child");fclose(logFile);return 0;
}




