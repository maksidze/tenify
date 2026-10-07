#define UNICODE
#define _UNICODE
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include "HashCheck.h"
#include "Adapters.h"
static HMODULE self;
__declspec(dllexport) volatile LONG SettingsContentStage;
__declspec(dllexport) volatile DWORD SettingsContentResult=E_PENDING;
/* Owned single-thread bootstrap only. Any failure prevents app continuation. */
__declspec(dllexport) DWORD WINAPI SettingsInitialize(void*unused){
 (void)unused;WCHAR folder[MAX_PATH],paths[3][MAX_PATH];
 if(SettingsContentStage==3)return 0;
 DWORD n=GetModuleFileNameW(self,folder,MAX_PATH);if(!n||n>=MAX_PATH)return E_FAIL;
 WCHAR*slash=wcsrchr(folder,L'\\');if(!slash)return E_FAIL;slash[1]=0;
 for(int i=0;i<3;i++){
  WCHAR combined[MAX_PATH];if(wcslen(folder)+wcslen(adapters[i].relative)>=MAX_PATH)return E_FAIL;
  wcscpy(combined,folder);wcscat(combined,adapters[i].relative);
  n=GetFullPathNameW(combined,MAX_PATH,paths[i],NULL);if(!n||n>=MAX_PATH)return E_FAIL;
  if(!hashMatches(paths[i],adapters[i].hash))return SettingsContentResult=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 }
 for(int i=0;i<3;i++){
  HMODULE m=LoadLibraryExW(paths[i],NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
  if(!m)return SettingsContentResult=HRESULT_FROM_WIN32(GetLastError());
  DWORD(WINAPI*init)(void*)=(void*)GetProcAddress(m,adapters[i].entry);
  if(!init)return SettingsContentResult=E_NOINTERFACE;
  DWORD result=init(NULL);SettingsContentResult=result;if(result)return result;
  InterlockedExchange(&SettingsContentStage,i+1);
 }
 return SettingsContentResult=0;
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD why,void*reserved){if(why==DLL_PROCESS_ATTACH){self=h;DisableThreadLibraryCalls(h);}return TRUE;}
