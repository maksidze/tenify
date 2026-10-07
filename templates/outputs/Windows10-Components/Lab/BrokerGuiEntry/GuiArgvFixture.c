#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
int wmain(int argc,wchar_t**argv){
 if(argc<2)return 64;FILE*f=_wfopen(argv[1],L"w, ccs=UTF-8");if(!f)return 65;
 fwprintf(f,L"PID=%lu\nCONSOLE=%p\nARGC=%d\n",GetCurrentProcessId(),GetConsoleWindow(),argc);
 for(int i=0;i<argc;i++)fwprintf(f,L"ARG%d=%ls\n",i,argv[i]);
 fclose(f);return 42;
}
