#include <shlobj.h>
/* Exact guarded CExtractIcon IExtractIconW slot,
   not the folded CExtractIconBase function. All callers keep genuine HRESULT. */
typedef HRESULT (STDMETHODCALLTYPE *LOCATION_FN)(void*,UINT,PWSTR,UINT,int*,UINT*);
static LOCATION_FN locationOriginal;static void**locationSlot;static SRWLOCK locationGate=SRWLOCK_INIT;static BOOL locationInstalled,locationTerminal;static DWORD locationProtection;static LONG locationHits,locationTooSmall;
static HRESULT STDMETHODCALLTYPE locationHook(void*that,UINT flags,PWSTR text,UINT count,int*index,UINT*outFlags){
 AcquireSRWLockShared(&locationGate);
 HRESULT hr=locationOriginal(that,flags,text,count,index,outFlags);
 if(locationInstalled&&hr==S_OK&&text&&count&&wmemchr(text,0,count)&&index&&outFlags&&!(*outFlags&GIL_NOTFILENAME)&&(*index==-3||*index==-4)){
  int route=pathIndex(text);
  if(route>=0){PCWSTR leaf=wcsrchr(routes[route].host,L'\\');leaf=leaf?leaf+1:routes[route].host;
   if(!_wcsicmp(leaf,L"imageres.dll")){size_t n=wcslen(routes[route].privatePath);if(n<count){memcpy(text,routes[route].privatePath,(n+1)*sizeof(WCHAR));InterlockedIncrement(&locationHits);}else InterlockedIncrement(&locationTooSmall);}
  }
 }
 ReleaseSRWLockShared(&locationGate);return hr;
}
static DWORD initializeFolderKey(BOOL fixture){
 WCHAR path[32768];if(!GetModuleFileNameW(NULL,path,32768))return ERROR_ACCESS_DENIED;
 if(fixture?(_wcsicmp(path,FIXTURE_PATH)||!hashMatches(path,FIXTURE_SHA)):(_wcsicmp(path,EXPLORER_PATH)||!hashMatches(path,EXPLORER_SHA)))return ERROR_ACCESS_DENIED;
 if(!hashMatches(L"C:\\Windows\\System32\\windows.storage.dll",STORAGE_SHA))return ERROR_REVISION_MISMATCH;
 AcquireSRWLockExclusive(&locationGate);DWORD result=0;
 if(locationTerminal){result=ERROR_INVALID_STATE;goto end;}
 if(locationInstalled){result=*locationSlot==(void*)locationHook?0:ERROR_BUSY;goto end;}
 HMODULE module=LoadLibraryExW(L"C:\\Windows\\System32\\windows.storage.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);if(!module){result=GetLastError();goto end;}
 WCHAR physical[32768],device[32768],expected[32768];
 if(!K32GetMappedFileNameW(GetCurrentProcess(),module,physical,32768)||!QueryDosDeviceW(L"C:",device,32768)){result=ERROR_REVISION_MISMATCH;goto end;}
 swprintf(expected,32768,L"%ls\\Windows\\System32\\windows.storage.dll",device);
 if(_wcsicmp(physical,expected)){result=ERROR_REVISION_MISMATCH;goto end;}
 if(memcmp((BYTE*)module+0x257930,locationBytes,sizeof(locationBytes))){result=ERROR_REVISION_MISMATCH;goto end;}
 locationSlot=(void**)((BYTE*)module+6628664+3*sizeof(void*));locationOriginal=(LOCATION_FN)((BYTE*)module+0x257930);
 if(*locationSlot!=(void*)locationOriginal){result=ERROR_BUSY;goto end;}
 if(!VirtualProtect(locationSlot,8,PAGE_READWRITE,&locationProtection)){result=GetLastError();goto end;}
 {void*prior=InterlockedCompareExchangePointer(locationSlot,(void*)locationHook,(void*)locationOriginal);DWORD ignore;if(!VirtualProtect(locationSlot,8,locationProtection,&ignore)||prior!=(void*)locationOriginal){locationTerminal=TRUE;result=ERROR_WRITE_FAULT;goto end;}}
 locationInstalled=TRUE;
end:ReleaseSRWLockExclusive(&locationGate);return result;
}
__declspec(dllexport) DWORD WINAPI InitializeFolderCacheKeyFixture(void*unused){(void)unused;return initializeFolderKey(TRUE);}
__declspec(dllexport) DWORD WINAPI RestoreFolderCacheKeyFixture(void*unused){
 (void)unused;AcquireSRWLockExclusive(&locationGate);DWORD result=0;
 if(locationTerminal){result=ERROR_INVALID_STATE;goto end;}
 if(locationInstalled){if(*locationSlot!=(void*)locationHook){result=ERROR_BUSY;goto end;}DWORD before,ignore;if(!VirtualProtect(locationSlot,8,PAGE_READWRITE,&before)){result=GetLastError();goto end;}
 void*observed=InterlockedCompareExchangePointer(locationSlot,(void*)locationOriginal,(void*)locationHook);
 BOOL protectionRestored=VirtualProtect(locationSlot,8,locationProtection,&ignore);
 if(!protectionRestored){locationTerminal=TRUE;result=ERROR_WRITE_FAULT;goto end;}
 if((observed!=(void*)locationHook&&observed!=(void*)locationOriginal)||*locationSlot!=(void*)locationOriginal){result=ERROR_BUSY;goto end;}
 locationInstalled=FALSE;}
end:ReleaseSRWLockExclusive(&locationGate);return result;
}
__declspec(dllexport) DWORD WINAPI GetFolderCacheKeyHits(void*unused){(void)unused;return locationHits;}
