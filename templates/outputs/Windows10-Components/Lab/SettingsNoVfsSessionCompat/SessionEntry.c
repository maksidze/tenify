#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include "EntryGuard.h"
static int entry(int argc,WCHAR**v){
 if(!v||argc!=7||wcscmp(v[1],L"--session")||wcscmp(v[3],L"-p")||wcscmp(v[5],L"-tid"))return 64;
 static WCHAR exe[32768],path[32768],state[32768],python[32768],callback[32768],cmd[32768];GetModuleFileNameW(NULL,exe,32768);WCHAR*slash=wcsrchr(exe,L'\\');if(!slash)return 65;slash[1]=0;
 // ConfigName is a nonce-only adjacent filename; arbitrary caller paths refused.
 if(wcslen(v[2])!=38||wcsncmp(v[2],L"s_",2)||wcscmp(v[2]+34,L".ini"))return 66;
 for(int i=2;i<34;i++)if(!((v[2][i]>=L'0'&&v[2][i]<=L'9')||(v[2][i]>=L'a'&&v[2][i]<=L'f')))return 66;
 unsigned long pid=wcstoul(v[4],NULL,10),tid=wcstoul(v[6],NULL,10);if(!pid||!tid)return 67;
 _snwprintf(path,32768,L"%ls%ls",exe,v[2]);
 GetPrivateProfileStringW(L"Session",L"State",L"",state,32768,path);GetPrivateProfileStringW(L"Session",L"Python",L"",python,32768,path);GetPrivateProfileStringW(L"Session",L"Callback",L"",callback,32768,path);
 if(!*state||!*python||!*callback||wcschr(state,L'"')||wcschr(python,L'"')||wcschr(callback,L'"'))return 68;
 int n=_snwprintf(cmd,32768,L"\"%ls\" \"%ls\" --state \"%ls\" -p %lu -tid %lu",python,callback,state,pid,tid);if(n<0||n>=32768)return 69;
 STARTUPINFOW si={sizeof(si)};PROCESS_INFORMATION pi={0};
 HANDLE job=CreateJobObjectW(NULL,NULL);JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
 if(!job||!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)))return (int)GetLastError();
 if(!CreateProcessW(python,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW|CREATE_SUSPENDED,NULL,NULL,&si,&pi)){DWORD e=GetLastError();CloseHandle(job);return (int)e;}
 pythonStarted=TRUE;
 if(!AssignProcessToJobObject(job,pi.hProcess)||ResumeThread(pi.hThread)==(DWORD)-1){DWORD e=GetLastError();TerminateProcess(pi.hProcess,0xdeca);WaitForSingleObject(pi.hProcess,5000);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseHandle(job);return (int)e;}
 CloseHandle(pi.hThread);DWORD result=0;DWORD waited=WaitForSingleObject(pi.hProcess,90000);
 if(waited==WAIT_TIMEOUT){TerminateProcess(pi.hProcess,0xdeca);WaitForSingleObject(pi.hProcess,5000);result=WAIT_TIMEOUT;}
 else if(waited!=WAIT_OBJECT_0||!GetExitCodeProcess(pi.hProcess,&result))result=GetLastError();
 CloseHandle(pi.hProcess);CloseHandle(job);return (int)result;
}
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){
 (void)a;(void)b;(void)c;(void)d;int argc=0;WCHAR**v=CommandLineToArgvW(GetCommandLineW(),&argc);int captured=0;WCHAR*session=NULL,*pidText=NULL,*tidText=NULL;BOOL malformed=FALSE;
 for(int i=1;v&&i<argc;i++){
  WCHAR**out=!wcscmp(v[i],L"--session")?&session:!wcscmp(v[i],L"-p")?&pidText:!wcscmp(v[i],L"-tid")?&tidText:NULL;
  if(out){if(*out||i+1>=argc){malformed=TRUE;break;}*out=v[++i];}
 }
 DWORD pid=0,tid=0;WCHAR*tail=NULL;
 if(pidText){pid=wcstoul(pidText,&tail,10);if(!pid||*tail)malformed=TRUE;}
 if(tidText){tid=wcstoul(tidText,&tail,10);if(!tid||*tail)malformed=TRUE;}
 if(v&&!malformed&&pid&&tid)captured=captureNative(pid,tid);
 if(!captured){if(v)LocalFree(v);return finishNative(ERROR_ACCESS_DENIED,0);}
 if(captured==2){DWORD r=ResumeThread(targetThread);LocalFree(v);return finishNative(r==(DWORD)-1?(int)GetLastError():0,0);}
 WCHAR*normalized[]={v[0],L"--session",session,L"-p",pidText,L"-tid",tidText};
 int result=session?entry(7,normalized):ERROR_INVALID_PARAMETER;LocalFree(v);return finishNative(result,captured);
}
