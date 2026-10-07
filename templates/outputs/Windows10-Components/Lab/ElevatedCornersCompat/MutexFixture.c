#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,PWSTR c,int d){(void)a;(void)b;(void)c;(void)d;int n;PWSTR*args=CommandLineToArgvW(GetCommandLineW(),&n);if(n!=3)return 2;HANDLE m=CreateMutexW(NULL,FALSE,L"Local\\CodexElevatedCornersLaunchV1");if(!m||WaitForSingleObject(m,2000)!=WAIT_OBJECT_0)return 3;HANDLE ready=CreateFileW(args[1],GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);if(ready==INVALID_HANDLE_VALUE)return 4;CloseHandle(ready);ULONGLONG end=GetTickCount64()+15000;while(GetTickCount64()<end&&GetFileAttributesW(args[2])==INVALID_FILE_ATTRIBUTES)Sleep(30);ReleaseMutex(m);CloseHandle(m);LocalFree(args);return 0;}
