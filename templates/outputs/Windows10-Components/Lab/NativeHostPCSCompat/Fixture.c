#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,PWSTR c,int d){int n;PWSTR*args=CommandLineToArgvW(GetCommandLineW(),&n);if(n!=2)return 2;FILE*f=_wfopen(args[1],L"wb");if(f){fprintf(f,"PrimaryRan after nativePCS-memory-bootstrap console=%p\n",GetConsoleWindow());fclose(f);}LocalFree(args);return 0;}
