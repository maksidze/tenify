#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h,DWORD reason,void*p){if(reason==DLL_PROCESS_ATTACH)Sleep(INFINITE);return TRUE;}
