#include <bcrypt.h>
#include "HashCheck.h"
#include "EntryPins.h"
static HANDLE targetProcess,targetThread;static BOOL pythonStarted;
static int captureNative(DWORD pid,DWORD tid){
 targetProcess=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE|SYNCHRONIZE,FALSE,pid);targetThread=OpenThread(THREAD_QUERY_LIMITED_INFORMATION|THREAD_SUSPEND_RESUME,FALSE,tid);
 if(!targetProcess||!targetThread||GetProcessIdOfThread(targetThread)!=pid||WaitForSingleObject(targetProcess,0)!=WAIT_TIMEOUT)return 0;
 FILETIME born,end,k,u,ownBorn;if(!GetProcessTimes(GetCurrentProcess(),&ownBorn,&end,&k,&u))return 0;
 if(!GetProcessTimes(targetProcess,&born,&end,&k,&u))return 0;
 ULONGLONG t=((ULONGLONG)born.dwHighDateTime<<32)|born.dwLowDateTime,o=((ULONGLONG)ownBorn.dwHighDateTime<<32)|ownBorn.dwLowDateTime;if(t>o||o-t>120ULL*10000000ULL)return 0;
 WCHAR path[32768],pkg[4096];DWORD n=32768;UINT pn=4096;
 if(!QueryFullProcessImageNameW(targetProcess,0,path,&n))return 0;
 typedef LONG(WINAPI*PKG)(HANDLE,UINT*,WCHAR*);PKG get=(PKG)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"GetPackageFullName");LONG result=get?get(targetProcess,&pn,pkg):ERROR_PROC_NOT_FOUND;
#ifdef OWN_ENTRY_FIXTURE
 if(result!=APPMODEL_ERROR_NO_PACKAGE||!hashMatches(path,ENTRY_FIXTURE_SHA))return 0;
 if(!_wcsicmp(path,ENTRY_FIXTURE_BROKER_PATH))return 2;
 return !_wcsicmp(path,ENTRY_FIXTURE_PATH)?1:0;
#else
 if(result||wcscmp(pkg,ENTRY_PACKAGE))return 0;
 if(!_wcsicmp(path,ENTRY_TARGET_PATH)&&hashMatches(path,ENTRY_TARGET_SHA))return 1;
 if(!_wcsicmp(path,L"C:\\Windows\\System32\\RuntimeBroker.exe")&&hashMatches(path,ENTRY_BROKER_SHA))return 2;
 return 0;
#endif
}
static int finishNative(int result,int captured){
 if(captured&&result){
  // Before Python starts there can be no injected hook. Preserve normal native
  // activation on missing/malformed config or absent Python. Once Python runs,
  // any uncertain failure must abort this exact captured process, never resume.
  if(pythonStarted){if(WaitForSingleObject(targetProcess,0)==WAIT_TIMEOUT){if(!TerminateProcess(targetProcess,0xdeca)||WaitForSingleObject(targetProcess,5000)!=WAIT_OBJECT_0)result=ERROR_BUSY;}}
  else if(ResumeThread(targetThread)==(DWORD)-1)result=(int)GetLastError();
 }
 if(targetThread)CloseHandle(targetThread);if(targetProcess)CloseHandle(targetProcess);return result;
}
