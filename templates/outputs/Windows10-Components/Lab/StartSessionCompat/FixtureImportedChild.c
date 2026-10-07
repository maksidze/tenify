#define UNICODE
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
extern __declspec(dllimport) HRESULT WINAPI importedFactory(void*,void*,void**) __asm__("?GetActivationFactoryByPCWSTR@@YAJPEAXAEAVGuid@Platform@@PEAPEAX@Z");
extern __declspec(dllimport) wchar_t** WINAPI importedArguments(int*) __asm__("?GetCmdArguments@Details@Platform@@YAPEAPEA_WPEAH@Z");
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){int n;WCHAR**v=CommandLineToArgvW(GetCommandLineW(),&n);if(n!=2)return 64;FILE*f=_wfopen(v[1],L"wb");if(!f)return 65;void*out=NULL;HRESULT result=importedFactory(NULL,NULL,&out);int count=0;importedArguments(&count);fprintf(f,"{\"Pid\":%lu,\"FactoryResult\":%ld,\"ArgumentsResult\":%d,\"Console\":%llu}",GetCurrentProcessId(),result,count,(unsigned long long)(ULONG_PTR)GetConsoleWindow());fclose(f);LocalFree(v);Sleep(60000);return 0;}
