#include <windows.h>
__declspec(dllexport) HRESULT WINAPI StartCompatGetFactory(void*name,void*iid,void**out){if(out)*out=NULL;return 0x5a;}
__declspec(dllexport) wchar_t** WINAPI StartCompatGetArguments(int*argc){if(argc)*argc=0x6a;return NULL;}
