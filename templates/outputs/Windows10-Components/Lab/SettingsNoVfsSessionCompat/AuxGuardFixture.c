#define UNICODE
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include "EntryGuard.h"
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){int argc;WCHAR**v=CommandLineToArgvW(GetCommandLineW(),&argc);if(argc!=2)return 64;FILE*f=_wfopen(v[1],L"w, ccs=UTF-8");if(!f)return 65;STARTUPINFOW si={sizeof(si)};PROCESS_INFORMATION pi={};WCHAR cmd[32768];_snwprintf(cmd,32768,L"\"%ls\"",ENTRY_AUX_PATH);if(!CreateProcessW(ENTRY_AUX_PATH,cmd,0,0,FALSE,CREATE_NO_WINDOW|CREATE_SUSPENDED,0,0,&si,&pi))return 66;
 targetProcess=pi.hProcess;targetThread=pi.hThread;BOOL role=primaryAux(ENTRY_AUX_PATH);targetProcess=targetThread=NULL;
 int noPackage=captureNative(pi.dwProcessId,pi.dwThreadId);finishNative(0,0);int foreign=captureNative(pi.dwProcessId,GetCurrentThreadId());finishNative(0,0);
 DWORD prior=SuspendThread(pi.hThread);if(prior!=(DWORD)-1)ResumeThread(pi.hThread);
 BOOL pass=role&&noPackage==0&&foreign==0&&prior==1;fwprintf(f,L"{\"Passed\":%ls,\"RealPinnedAuxPrimaryRole\":%ls,\"NoPackageRejected\":%ls,\"ForeignThreadRejected\":%ls,\"OriginalSuspendCount\":%lu,\"NoUI\":true,\"NoRegistration\":true}\n",pass?L"true":L"false",role?L"true":L"false",noPackage==0?L"true":L"false",foreign==0?L"true":L"false",prior);fclose(f);
 TerminateProcess(pi.hProcess,0xdeca);WaitForSingleObject(pi.hProcess,5000);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);LocalFree(v);return pass?0:1;}
