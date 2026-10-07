#define UNICODE
#include <windows.h>
#include <stdio.h>
#include "EntryGuard.h"
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){
 const DWORD pid=3772,tid=5676;const ULONGLONG expectedBorn=134357668685014266ULL;
 targetProcess=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|SYNCHRONIZE,FALSE,pid);targetThread=OpenThread(THREAD_QUERY_INFORMATION|THREAD_QUERY_LIMITED_INFORMATION|THREAD_SUSPEND_RESUME,FALSE,tid);
 BOOL okay=targetProcess&&targetThread&&GetProcessIdOfThread(targetThread)==pid&&WaitForSingleObject(targetProcess,0)==WAIT_TIMEOUT;FILETIME born,end,k,u;WCHAR path[32768],pkg[4096];DWORD n=32768;UINT pn=4096;
 typedef LONG(WINAPI*PKG)(HANDLE,UINT*,PWSTR);PKG get=(PKG)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"GetPackageFullName");
 if(okay)okay=GetProcessTimes(targetProcess,&born,&end,&k,&u)&&(((ULONGLONG)born.dwHighDateTime<<32)|born.dwLowDateTime)==expectedBorn&&QueryFullProcessImageNameW(targetProcess,0,path,&n)&&!_wcsicmp(path,ENTRY_AUX_PATH)&&hashMatches(path,ENTRY_AUX_SHA)&&get&&!get(targetProcess,&pn,pkg)&&!wcscmp(pkg,ENTRY_PACKAGE)&&primaryAux(ENTRY_AUX_PATH);
 DWORD previous=(DWORD)-1,waited=WAIT_FAILED,exitCode=STILL_ACTIVE;if(okay){previous=ResumeThread(targetThread);if(previous!=(DWORD)-1){waited=WaitForSingleObject(targetProcess,10000);GetExitCodeProcess(targetProcess,&exitCode);}}
 FILE*f=_wfopen(L"@WORKSPACE_ESC@\\outputs\\Windows10-Components\\Lab\\SettingsNoVfsSessionCompat\\visibility3772-resume-proof.json",L"w, ccs=UTF-8");if(f){fwprintf(f,L"{\"PID\":3772,\"Birth\":134357668685014266,\"TID\":5676,\"ExactIdentityAndPrimaryRole\":%ls,\"PriorSuspendCount\":%lu,\"WaitResult\":%lu,\"ExitCode\":%lu,\"NoInjection\":true,\"NoTerminate\":true}\n",okay?L"true":L"false",previous,waited,exitCode);fclose(f);}
 if(targetThread)CloseHandle(targetThread);if(targetProcess)CloseHandle(targetProcess);return okay&&previous==1&&waited==WAIT_OBJECT_0?0:1;}
