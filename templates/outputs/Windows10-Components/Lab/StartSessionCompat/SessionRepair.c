/* Orphaned registration recovery, only the exact native Start package/command.
   This helper is inert unless the exact single default REG_SZ value matches. */
#define UNICODE
#define _UNICODE
#define COBJMACROS
#include <windows.h>
#include <shellapi.h>
#include <initguid.h>
#include <shobjidl.h>
#include <stdio.h>
#include <wchar.h>
static DWORD WINAPI timeout(void*p){Sleep(15000);ExitProcess(0xdecf);return 0;}
typedef HRESULT(WINAPI*GetClass)(const GUID*,const GUID*,void**);
static HRESULT debug(IPackageDebugSettings**out){HRESULT hr=CoCreateInstance(&CLSID_PackageDebugSettings,NULL,CLSCTX_INPROC_SERVER,&IID_IPackageDebugSettings,(void**)out);if(SUCCEEDED(hr))return hr;HMODULE h=LoadLibraryExW(L"twinapi.appcore.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);GetClass get=h?(GetClass)GetProcAddress(h,"DllGetClassObject"):NULL;if(!get)return hr;IClassFactory*f=NULL;hr=get(&CLSID_PackageDebugSettings,&IID_IClassFactory,(void**)&f);if(SUCCEEDED(hr)){hr=IClassFactory_CreateInstance(f,NULL,&IID_IPackageDebugSettings,(void**)out);IClassFactory_Release(f);}return hr;}
static BOOL singleValue(PCWSTR key,PCWSTR expected){HKEY h;LONG e=RegOpenKeyExW(HKEY_CURRENT_USER,key,0,KEY_READ,&h);if(e!=ERROR_SUCCESS)return FALSE;DWORD subs=0,values=0,type=0,bytes=0;BOOL valid=RegQueryInfoKeyW(h,NULL,NULL,NULL,&subs,NULL,NULL,&values,NULL,NULL,NULL,NULL)==ERROR_SUCCESS&&!subs&&values==1&&RegQueryValueExW(h,L"",NULL,&type,NULL,&bytes)==ERROR_SUCCESS&&type==REG_SZ&&bytes==(wcslen(expected)+1)*2;WCHAR value[4096];if(valid)valid=bytes<=sizeof(value)&&RegQueryValueExW(h,L"",NULL,&type,(BYTE*)value,&bytes)==ERROR_SUCCESS&&!wcscmp(value,expected);RegCloseKey(h);return valid;}
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){int n;WCHAR**v=CommandLineToArgvW(GetCommandLineW(),&n);if(!v||n!=4)return 64;PCWSTR prefix=L"Microsoft.Windows.StartMenuExperienceHost_";if(wcsncmp(v[1],prefix,wcslen(prefix))||wcschr(v[1],L'\\')||wcschr(v[1],L'/')||wcslen(v[1])>512)return 64;WCHAR*name=wcsstr(v[2],L" --session s_");if(!name||wcslen(name)!=49||wcscmp(name+45,L".ini"))return 64;PCWSTR nonce=name+13;for(int i=0;i<32;i++)if(!((nonce[i]>=L'0'&&nonce[i]<=L'9')||(nonce[i]>=L'a'&&nonce[i]<=L'f')))return 64;WCHAR own[32768];DWORD length=GetModuleFileNameW(NULL,own,32768);if(!length||length>=32768)return 64;WCHAR*slash=wcsrchr(own,L'\\');if(!slash)return 64;wcscpy(slash+1,L"Start10SessionDebugger.exe");if((size_t)(name-v[2])!=wcslen(own)||_wcsnicmp(v[2],own,wcslen(own)))return 64;
 WCHAR mutexName[128];swprintf(mutexName,128,L"Local\\StartSessionRestore_%.*ls",32,nonce);HANDLE gate=CreateMutexW(NULL,FALSE,mutexName);if(!gate)return 65;DWORD acquired=WaitForSingleObject(gate,10000);if(acquired!=WAIT_OBJECT_0&&acquired!=WAIT_ABANDONED){CloseHandle(gate);return 66;}HANDLE watchdog=CreateThread(NULL,0,timeout,NULL,0,NULL);if(!watchdog){ReleaseMutex(gate);CloseHandle(gate);return 67;}
 WCHAR key[4096];swprintf(key,4096,L"Software\\Classes\\ActivatableClasses\\Package\\%ls\\DebugInformation",v[1]);HKEY h;LONG exists=RegOpenKeyExW(HKEY_CURRENT_USER,key,0,KEY_READ,&h);if(exists==ERROR_SUCCESS)RegCloseKey(h);BOOL allowed=exists==ERROR_FILE_NOT_FOUND;swprintf(key,4096,L"Software\\Microsoft\\Windows\\CurrentVersion\\PackagedAppXDebug\\%ls",v[1]);allowed=allowed&&singleValue(key,v[2]);HRESULT hr=S_FALSE;
 if(allowed){hr=CoInitializeEx(NULL,COINIT_MULTITHREADED);if(SUCCEEDED(hr)){IPackageDebugSettings*p=NULL;hr=debug(&p);if(SUCCEEDED(hr)){hr=IPackageDebugSettings_DisableDebugging(p,v[1]);IPackageDebugSettings_Release(p);}CoUninitialize();}}
 FILE*f=_wfopen(v[3],L"ab");if(f){fprintf(f,"ExactSingleRegistration=%d HRESULT=%08lx\n",allowed,hr);fclose(f);}ReleaseMutex(gate);CloseHandle(gate);CloseHandle(watchdog);LocalFree(v);return FAILED(hr)?1:0;
}
