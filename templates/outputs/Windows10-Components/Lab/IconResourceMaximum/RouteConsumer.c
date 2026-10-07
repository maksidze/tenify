#define WIN32_LEAN_AND_MEAN
#include <windows.h>
__declspec(dllexport) HICON WINAPI LoadShield(void){return LoadImageW(GetModuleHandleW(L"user32.dll"),MAKEINTRESOURCEW(106),IMAGE_ICON,32,32,0);}
BOOL WINAPI DllMain(HINSTANCE m,DWORD reason,void*reserved){(void)m;(void)reason;(void)reserved;return TRUE;}
