#include <bcrypt.h>
#include "HashCheck.h"
#include "EntryPins.h"
#include <psapi.h>
static HANDLE targetProcess,targetThread;static BOOL pythonStarted;
static BOOL primaryAux(PCWSTR expected){
 typedef LONG(WINAPI*QUERY)(HANDLE,ULONG,void*,ULONG,ULONG*);QUERY q=(QUERY)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationThread");void*start=NULL;ULONG used=0;
 if(!q||q(targetThread,9,&start,sizeof(start),&used)<0||!start)return FALSE;
 MEMORY_BASIC_INFORMATION mbi={};if(!VirtualQueryEx(targetProcess,start,&mbi,sizeof(mbi))||mbi.Type!=MEM_IMAGE)return FALSE;
 WCHAR mapped[32768],opened[32768];if(!K32GetMappedFileNameW(targetProcess,start,mapped,32768))return FALSE;
 HANDLE file=CreateFileW(expected,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,0,OPEN_EXISTING,0,0);if(file==INVALID_HANDLE_VALUE)return FALSE;
 BOOL result=FALSE;IMAGE_DOS_HEADER dos={};IMAGE_NT_HEADERS64 nt={};DWORD got=0;LARGE_INTEGER at={};
 DWORD n=GetFinalPathNameByHandleW(file,opened,32768,VOLUME_NAME_NT);
 if(n&&n<32768&&!_wcsicmp(mapped,opened)&&ReadFile(file,&dos,sizeof(dos),&got,0)&&got==sizeof(dos)&&dos.e_magic==IMAGE_DOS_SIGNATURE&&dos.e_lfanew>0){at.QuadPart=dos.e_lfanew;if(SetFilePointerEx(file,at,0,FILE_BEGIN)&&ReadFile(file,&nt,sizeof(nt),&got,0)&&got==sizeof(nt)&&nt.Signature==IMAGE_NT_SIGNATURE&&nt.OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC&&start==(BYTE*)mbi.AllocationBase+nt.OptionalHeader.AddressOfEntryPoint){FILETIME processBorn,threadBorn,end,k,u;if(GetProcessTimes(targetProcess,&processBorn,&end,&k,&u)&&GetThreadTimes(targetThread,&threadBorn,&end,&k,&u)){ULONGLONG p=((ULONGLONG)processBorn.dwHighDateTime<<32)|processBorn.dwLowDateTime,t=((ULONGLONG)threadBorn.dwHighDateTime<<32)|threadBorn.dwLowDateTime;result=t>=p&&t-p<=2ULL*10000000ULL;}}}
 CloseHandle(file);return result;
}
static int captureNative(DWORD pid,DWORD tid){
 targetProcess=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_TERMINATE|SYNCHRONIZE,FALSE,pid);targetThread=OpenThread(THREAD_QUERY_INFORMATION|THREAD_QUERY_LIMITED_INFORMATION|THREAD_SUSPEND_RESUME,FALSE,tid);
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
 if(!_wcsicmp(path,ENTRY_AUX_PATH)&&hashMatches(path,ENTRY_AUX_SHA)&&primaryAux(ENTRY_AUX_PATH))return 2;
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
