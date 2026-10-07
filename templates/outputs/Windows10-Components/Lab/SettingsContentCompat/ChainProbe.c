#define UNICODE
#define _UNICODE
#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>
typedef DWORD(WINAPI*Init)(void*);
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){
 int argc;WCHAR**argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(argc!=3)return 64;
 FILE*log=_wfopen(argv[1],L"wb");if(!log)return 65;
 HRESULT co=CoInitializeEx(NULL,COINIT_MULTITHREADED);fprintf(log,"CoInitialize=%08lx\n",co);fflush(log);if(FAILED(co))return 1;
 HMODULE mod=LoadLibraryExW(argv[2],NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
 Init init=mod?(Init)GetProcAddress(mod,"SettingsInitialize"):NULL;if(!init){fprintf(log,"LoadError=%lu\n",GetLastError());return 2;}
 DWORD result=init(NULL);fprintf(log,"Initialize=%08lx\n",result);fflush(log);if(result)return 3;
 const WCHAR*modules[]={L"SettingsCaptionCompat.dll",L"SettingsControlTextCompat.dll",L"SettingsPowerCompat.dll"};
 const char*restore[]={"SettingsCaptionRestore","SettingsControlTextRestore","SettingsPowerRestore"};
 for(int i=2;i>=0;i--){HMODULE h=GetModuleHandleW(modules[i]);Init r=h?(Init)GetProcAddress(h,restore[i]):NULL;result=r?r(NULL):E_NOINTERFACE;fprintf(log,"Restore_%ls=%08lx\n",modules[i],result);fflush(log);if(result)return 4;}
 fprintf(log,"COMPLETE own process initialization and reverse restore\n");fclose(log);CoUninitialize();LocalFree(argv);return 0;
}
