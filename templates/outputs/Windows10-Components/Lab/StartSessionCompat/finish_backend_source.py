"""One-time private source changes; no production files or process changes."""
from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent
p=H/'StartSessionBackend.c';s=p.read_text(encoding='utf-8-sig')
def rep(a,b):
 global s
 assert s.count(a)==1,(a[:90],s.count(a));s=s.replace(a,b)
rep('#include "StartCompatTrace.h"','#include "StartCompatTrace.h"\n#include "SessionLifetime.h"\n#include <io.h>')
rep('static BOOL sessionUntilStop;','static BOOL sessionUntilStop;\nstatic ULONGLONG sessionExpectedBirth;')
rep('sessionUntilStop=GetPrivateProfileIntW(L"Debugger",L"UntilStop",0,config)!=0;','sessionUntilStop=GetPrivateProfileIntW(L"Debugger",L"UntilStop",0,config)!=0;\n  wchar_t expectedBirth[32];GetPrivateProfileStringW(L"Debugger",L"TargetBirth",L"",expectedBirth,32,config);sessionExpectedBirth=wcstoull(expectedBirth,NULL,10);')
rep('static void logline(const char *format,...){','static void logline(const char *format,...){if(ftell(logFile)>8*1024*1024){fflush(logFile);_chsize(_fileno(logFile),0);fseek(logFile,0,SEEK_SET);fputs("LOG rolled; bounded8MiB\\n",logFile);}')
rep('BOOL exact=pi.hProcess&&QueryFullProcessImageNameW', 'BOOL exact=pi.hProcess&&sessionExpectedBirth&&sessionFileTimeValue(&born)==sessionExpectedBirth&&QueryFullProcessImageNameW')
rep('if(!created){if(attached&&pi.hThread)ResumeThread(pi.hThread);CloseDesktop(desk);fclose(logFile);return 2;}','if(!created){if(attached&&pi.hThread)ResumeThread(pi.hThread);if(pi.hThread)CloseHandle(pi.hThread);if(pi.hProcess)CloseHandle(pi.hProcess);CloseDesktop(desk);fclose(logFile);return 2;}')
rep('ULONGLONG nextSnapshot=GetTickCount64()+5000;','SESSION_LIFETIME lifetime={0};if(!sessionOwner||!sessionLifetimeStart(&lifetime,pi.hProcess,sessionOwner,sessionCancel,seconds,sessionUntilStop)){TerminateProcess(pi.hProcess,0xdecd);DebugActiveProcessStop(childPid);ExitProcess(0xdecd);}\n ULONGLONG nextSnapshot=GetTickCount64()+5000;')
rep('else if(e.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT){if(e.u.CreateThread.hThread)CloseHandle(e.u.CreateThread.hThread);}','else if(e.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT){/* Debug-event handle is Windows-owned; Continue(EXIT_THREAD) or detach closes it. */}')
rep('ContinueDebugEvent(e.dwProcessId,e.dwThreadId,disposition);','if(!ContinueDebugEvent(e.dwProcessId,e.dwThreadId,disposition)){logline("EVENT_CONTINUE_FAILED code=%lu tid=%lu error=%lu",e.dwDebugEventCode,e.dwThreadId,GetLastError());TerminateProcess(pi.hProcess,0xdecb);stopping=TRUE;drain=GetTickCount64()+3000;detachRequested=FALSE;}')
rep('CheckRemoteDebuggerPresent(pi.hProcess,&stillDebugged);','if(!CheckRemoteDebuggerPresent(pi.hProcess,&stillDebugged))stillDebugged=TRUE;')
rep('if(detached&&!stillDebugged&&sessionUntilStop){deadline=~0ULL;logline("SESSION UntilStop after bounded bootstrap; exact owner handle + durable cancel");}', 'if(detached&&!stillDebugged){wchar_t readyPath[32768];swprintf(readyPath,32768,L"%ls.ready",argv[1]);HANDLE f=CreateFileW(readyPath,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,0,NULL);DWORD written=0;const char ok[]="Detached=1\\nRemoteDebugger=0\\n";BOOL marked=f!=INVALID_HANDLE_VALUE&&WriteFile(f,ok,sizeof(ok)-1,&written,NULL)&&written==sizeof(ok)-1&&FlushFileBuffers(f);if(f!=INVALID_HANDLE_VALUE)CloseHandle(f);if(!marked){TerminateProcess(pi.hProcess,0xdecc);stopping=TRUE;drain=GetTickCount64()+3000;}else{sessionLifetimeReady(&lifetime);if(sessionUntilStop)deadline=~0ULL;logline("SESSION ready untilStop=%d; bounded bootstrap complete, owner/cancel lifetime",sessionUntilStop);}}')
rep('if(!detached){TerminateProcess(pi.hProcess,0xdec4);','if(!detached||stillDebugged){TerminateProcess(pi.hProcess,0xdec4);')
rep('CloseHandle(pi.hThread);CloseHandle(pi.hProcess);if(sessionOwner)', 'if(!sessionLifetimeStop(&lifetime))ExitProcess(0xdecf);if(injectThread)CloseHandle(injectThread);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);if(sessionOwner)')
p.write_text(s,encoding='utf-8')
p=H/'StartSessionEntry.c';s=p.read_text(encoding='utf-8-sig')
rep('CloseHandle(process);WCHAR p[20],t[20];','WCHAR p[20],t[20];')
rep('if(veh)RemoveVectoredExceptionHandler(veh);','CloseHandle(process);if(veh)RemoveVectoredExceptionHandler(veh);')
rep('OwnerPath=%ls\\r\\n",report,','OwnerPath=%ls\\r\\nTargetBirth=%llu\\r\\n",report,')
rep('untilStop,v[5],v[6],v[7]);','untilStop,v[5],v[6],v[7],birth);')
p.write_text(s,encoding='utf-8')
print('Private backend/entry prepared; Windows-owned event handle fix, exact held birth, independent lifetime watchdog, ready marker.')
