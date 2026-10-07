#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>
#include <stdint.h>
#include <stdlib.h>
extern int BrokerExistingWmain(int,wchar_t**);
static HANDLE dispatchTrace=INVALID_HANDLE_VALUE;
static void trace(const char*s){if(dispatchTrace!=INVALID_HANDLE_VALUE){DWORD n;WriteFile(dispatchTrace,s,(DWORD)strlen(s),&n,NULL);FlushFileBuffers(dispatchTrace);}}
static LONG CALLBACK exceptionTrace(PEXCEPTION_POINTERS e){if(e->ExceptionRecord->ExceptionCode==0xc0000005||e->ExceptionRecord->ExceptionCode==0xc00000fd||e->ExceptionRecord->ExceptionCode==0xc0000409){char line[256];snprintf(line,sizeof(line),"EXCEPTION code=%08lx address=%p rip=%llx rsp=%llx\r\n",e->ExceptionRecord->ExceptionCode,e->ExceptionRecord->ExceptionAddress,e->ContextRecord->Rip,e->ContextRecord->Rsp);trace(line);}return EXCEPTION_CONTINUE_SEARCH;}
static void invalidParameter(const WCHAR*expression,const WCHAR*function,const WCHAR*file,unsigned line,uintptr_t reserved){char text[1024];snprintf(text,sizeof(text),"CRT_INVALID_PARAMETER line=%u function=%ls expression=%ls file=%ls\r\n",line,function?function:L"",expression?expression:L"",file?file:L"");trace(text);ExitProcess(3);}
typedef LONG(WINAPI*PackageFn)(HANDLE,UINT*,WCHAR*);
static ULONGLONG filetimeValue(const FILETIME*f){return ((ULONGLONG)f->dwHighDateTime<<32)|f->dwLowDateTime;}
static void resume(DWORD pid,DWORD tid){HANDLE t=OpenThread(THREAD_SUSPEND_RESUME|THREAD_QUERY_LIMITED_INFORMATION,FALSE,tid);if(t){if(GetProcessIdOfThread(t)==pid)ResumeThread(t);CloseHandle(t);}}
static BOOL present(PCWSTR p){return p[0]&&GetFileAttributesW(p)!=INVALID_FILE_ATTRIBUTES;}
static BOOL put(PCWSTR p,PCWSTR data){HANDLE f=CreateFileW(p,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,0,NULL);if(f==INVALID_HANDLE_VALUE)return FALSE;WORD bom=0xfeff;DWORD n;DWORD bytes=(DWORD)(wcslen(data)*2);BOOL ok=WriteFile(f,&bom,2,&n,NULL)&&n==2&&WriteFile(f,data,bytes,&n,NULL)&&n==bytes&&FlushFileBuffers(f);CloseHandle(f);return ok;}
static BOOL recordMatches(PCWSTR path,DWORD pid,ULONGLONG born){struct{DWORD magic,pid;ULONGLONG born;}r={0};HANDLE f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);if(f==INVALID_HANDLE_VALUE)return FALSE;LARGE_INTEGER size;DWORD read=0;BOOL same=GetFileSizeEx(f,&size)&&size.QuadPart==sizeof(r)&&ReadFile(f,&r,sizeof(r),&read,NULL)&&read==sizeof(r)&&r.magic==0x53534c31&&r.pid==pid&&r.born==born;CloseHandle(f);return same;}
static void repairOrphan(PCWSTR base,PCWSTR session,PCWSTR package,PCWSTR directory){
#ifndef SESSION_ENTRY_FIXTURE
 WCHAR exe[32768],debugger[32768],command[32768],args[32768];swprintf(exe,32768,L"%lsSessionRepair.exe",base);swprintf(debugger,32768,L"%lsStart10SessionDebugger.exe --session %ls",base,session);swprintf(args,32768,L"\"%ls\" \"%ls\" \"%ls\" \"%ls\\orphan-repair.log\"",exe,package,debugger,directory);STARTUPINFOW si={sizeof(si)};PROCESS_INFORMATION pi={0};if(CreateProcessW(exe,args,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,base,&si,&pi)){CloseHandle(pi.hThread);CloseHandle(pi.hProcess);}
#endif
}
int WINAPI wWinMain(HINSTANCE i,HINSTANCE previous,LPWSTR cmd,int show){
 (void)i;(void)previous;(void)cmd;(void)show;int argc=0;WCHAR**argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(!argv)return 87;
 DWORD pid=0,tid=0;WCHAR sessionName[256]={0};for(int a=1;a+1<argc;a++){if(!wcscmp(argv[a],L"-p"))pid=wcstoul(argv[a+1],NULL,10);if(!wcscmp(argv[a],L"-tid"))tid=wcstoul(argv[a+1],NULL,10);if(!wcscmp(argv[a],L"--session"))wcsncpy(sessionName,argv[a+1],255);}
 if(!pid||!tid||!sessionName[0]||wcschr(sessionName,L':')||wcschr(sessionName,L'\\')||wcschr(sessionName,L'/')){resume(pid,tid);LocalFree(argv);return 64;}
 static WCHAR session[32768],base[32768];GetModuleFileNameW(NULL,base,32768);WCHAR*slash=wcsrchr(base,L'\\');if(!slash){resume(pid,tid);LocalFree(argv);return 65;}slash[1]=0;swprintf(session,32768,L"%ls%ls",base,sessionName);
 const WCHAR*keys[]={L"Target",L"PackageFullName",L"Directory",L"CancelFile",L"Proxy",L"OwnerPid",L"OwnerBirth",L"OwnerPath",L"DeadlineTick",L"UntilStop",L"ServerArgument"};static WCHAR v[11][32768];for(int a=0;a<11;a++)GetPrivateProfileStringW(L"Session",keys[a],L"",v[a],32768,session);
 for(int a=0;a<11;a++){if(!v[a][0]){resume(pid,tid);LocalFree(argv);return 67;}}
 ULONGLONG deadline=wcstoull(v[8],NULL,10),now=GetTickCount64();BOOL untilStop=wcstoul(v[9],NULL,10)!=0;
 HANDLE owner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,wcstoul(v[5],NULL,10));FILETIME ob,oe,ok,ou;WCHAR ownerPath[32768];DWORD ownerLength=32768;
 BOOL ownerValid=owner&&WaitForSingleObject(owner,0)==WAIT_TIMEOUT&&GetProcessTimes(owner,&ob,&oe,&ok,&ou)&&filetimeValue(&ob)==wcstoull(v[6],NULL,10)&&QueryFullProcessImageNameW(owner,0,ownerPath,&ownerLength)&&!_wcsicmp(ownerPath,v[7]);
 if(owner)CloseHandle(owner);
 BOOL cancelled=present(v[3])||!ownerValid||(!untilStop&&(!deadline||now>=deadline));
 HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE|SYNCHRONIZE,FALSE,pid);static WCHAR observed[32768]={0},pkg[4096]={0};DWORD n=32768;UINT pn=4096;FILETIME born,e,k,u,ft;GetSystemTimeAsFileTime(&ft);PackageFn get=(PackageFn)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"GetPackageFullName");
 BOOL packageMatch=process&&get&&get(process,&pn,pkg)==0&&!wcscmp(pkg,v[1]);
#ifdef SESSION_ENTRY_FIXTURE
 // Only the separate fixture binary accepts an unpackaged harmless GUI child.
 packageMatch=process&&get&&get(process,&pn,pkg)==APPMODEL_ERROR_NO_PACKAGE&&!wcscmp(v[1],L"OWN-UNPACKAGED-FIXTURE");
#endif
 HANDLE thread=OpenThread(THREAD_QUERY_LIMITED_INFORMATION,FALSE,tid);BOOL exact=process&&thread&&GetProcessIdOfThread(thread)==pid&&QueryFullProcessImageNameW(process,0,observed,&n)&&!_wcsicmp(observed,v[0])&&GetProcessTimes(process,&born,&e,&k,&u)&&packageMatch;if(thread)CloseHandle(thread);
 ULONGLONG birth=exact?filetimeValue(&born):0,age=exact?filetimeValue(&ft)-birth:~0ULL;exact=exact&&age<300000000ULL;
 if(!exact){resume(pid,tid);if(process)CloseHandle(process);LocalFree(argv);return 0;}
 if(!ownerValid){/* New callback after controller/logon ended: it is still native and unmodified. */repairOrphan(base,sessionName,v[1],v[2]);resume(pid,tid);CloseHandle(process);LocalFree(argv);return 0;}
 if(cancelled){TerminateProcess(process,0xdeca);WaitForSingleObject(process,5000);CloseHandle(process);LocalFree(argv);return 0;}
 DWORD seconds=untilStop?30:(DWORD)((deadline-now+999)/1000);if(seconds>3600)seconds=3600;
 static WCHAR prefix[32768],record[32768],recordTmp[32768],report[32768],config[32768],text[32768];swprintf(prefix,32768,L"%ls\\a_%lu_%016llx",v[2],pid,birth);swprintf(record,32768,L"%ls.record",prefix);swprintf(recordTmp,32768,L"%ls.pending-%lu",prefix,GetCurrentProcessId());swprintf(report,32768,L"%ls.log",prefix);swprintf(config,32768,L"%ls.ini",prefix);
 struct{DWORD magic,pid;ULONGLONG born;}r={0x53534c31,pid,birth};HANDLE rf=CreateFileW(recordTmp,GENERIC_WRITE,0,NULL,CREATE_NEW,0,NULL);DWORD written=0;BOOL owned=rf!=INVALID_HANDLE_VALUE&&WriteFile(rf,&r,sizeof(r),&written,NULL)&&written==sizeof(r)&&FlushFileBuffers(rf);if(rf!=INVALID_HANDLE_VALUE)CloseHandle(rf);owned=owned&&MoveFileExW(recordTmp,record,MOVEFILE_WRITE_THROUGH);if(!owned){DeleteFileW(recordTmp);BOOL duplicate=recordMatches(record,pid,birth);/* An existing exact bootstrap owns the suspend count. Never resume it here. */if(!duplicate){TerminateProcess(process,0xdecc);WaitForSingleObject(process,5000);}CloseHandle(process);LocalFree(argv);return duplicate?0:66;}
 // Durable identity is visible to the independent guard BEFORE backend creates its claim.
#ifdef SESSION_ENTRY_FIXTURE
 Sleep(500); // Deterministic cancellation interleaving at the actual durable gate.
#endif
 if(present(v[3])||(!untilStop&&GetTickCount64()>=deadline)){TerminateProcess(process,0xdeca);WaitForSingleObject(process,5000);CloseHandle(process);LocalFree(argv);return 0;}
 ULONGLONG expiry=filetimeValue(&ft)+10000000ULL*seconds;
 swprintf(text,32768,L"[Debugger]\r\nReport=%ls\r\nTarget=%ls\r\nSeconds=%lu\r\nServerArgument=%ls\r\nProxy=%ls\r\nPackageFullName=%ls\r\nDeadlineFileTime=%llu\r\nCancelFile=%ls\r\nDetachAfterBootstrap=1\r\nUntilStop=%u\r\nOwnerPid=%ls\r\nOwnerBirth=%ls\r\nOwnerPath=%ls\r\nTargetBirth=%llu\r\n",report,v[0],seconds,v[10],v[4],v[1],expiry,v[3],untilStop,v[5],v[6],v[7],birth);
 if(!put(config,text)){TerminateProcess(process,0xdeca);WaitForSingleObject(process,5000);CloseHandle(process);LocalFree(argv);return 66;}
 WCHAR p[20],t[20];swprintf(p,20,L"%lu",pid);swprintf(t,20,L"%lu",tid);WCHAR*backend[]={argv[0],L"--config",config,L"-p",p,L"-tid",t};
 swprintf(recordTmp,32768,L"%ls.dispatch.log",prefix);dispatchTrace=CreateFileW(recordTmp,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,0,NULL);
 ULONG guarantee=65536;SetThreadStackGuarantee(&guarantee);void*veh=AddVectoredExceptionHandler(1,exceptionTrace);_set_invalid_parameter_handler(invalidParameter);trace("BEFORE existing backend\r\n");SetLastError(0);
 int result=BrokerExistingWmain(7,backend);DWORD error=GetLastError();char line[128];snprintf(line,sizeof(line),"AFTER existing backend result=%d error=%lu\r\n",result,error);trace(line);CloseHandle(process);if(veh)RemoveVectoredExceptionHandler(veh);if(dispatchTrace!=INVALID_HANDLE_VALUE)CloseHandle(dispatchTrace);LocalFree(argv);return result;
}
