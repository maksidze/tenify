#include <windows.h>
HRESULT WINAPI FixtureOriginalFactory(void*name,void*iid,void**out){if(out)*out=NULL;return 0x11;}
wchar_t** WINAPI FixtureOriginalArguments(int*argc){if(argc)*argc=0x22;return NULL;}
