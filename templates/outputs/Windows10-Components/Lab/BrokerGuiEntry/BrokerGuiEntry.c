// Production broker debuggers must not request a console / delegated Windows Terminal.
// Keep their existing CLI parser and file logging exactly in wmain.
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
extern int wmain(int argc,wchar_t**argv);
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE previous,LPWSTR command,int show){
 (void)instance;(void)previous;(void)command;(void)show;
 int argc=0;LPWSTR*argv=CommandLineToArgvW(GetCommandLineW(),&argc);
 if(!argv)return 87;
 int result=wmain(argc,argv);
 LocalFree(argv);
 return result;
}
