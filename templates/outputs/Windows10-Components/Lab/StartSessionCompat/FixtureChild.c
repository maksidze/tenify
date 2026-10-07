#define UNICODE
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){int n;WCHAR**v=CommandLineToArgvW(GetCommandLineW(),&n);if(n!=2)return 64;FILE*f=_wfopen(v[1],L"wb");if(!f)return 65;fprintf(f,"console=%p\n",GetConsoleWindow());fclose(f);LocalFree(v);Sleep(60000);return 0;}
