#define UNICODE
#include <windows.h>
#include <shellapi.h>
#include <wchar.h>
#include <stdlib.h>
#include "SessionLifetime.h"
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){int n;WCHAR**v=CommandLineToArgvW(GetCommandLineW(),&n);if(n!=4)return 64;HANDLE child=OpenProcess(PROCESS_TERMINATE|PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,wcstoul(v[1],NULL,10));WCHAR path[32768];DWORD size=32768;FILETIME born,e,k,u;BOOL exact=child&&GetProcessTimes(child,&born,&e,&k,&u)&&(((ULONGLONG)born.dwHighDateTime<<32)|born.dwLowDateTime)==wcstoull(v[2],NULL,10)&&QueryFullProcessImageNameW(child,0,path,&size)&&!_wcsicmp(path,v[3]);if(!exact)return 65;SESSION_LIFETIME state;if(!sessionLifetimeStart(&state,child,GetCurrentProcess(),L"",1,FALSE))return 66;Sleep(INFINITE);return 67;}
