#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>
#include "../SettingsContentCompat/HashCheck.h"

/* Native CDefView::_DoContextMenuPopup: choose the same Mode=1 branch used
 * when ShouldShowMiniMenu returns false. No replacement COM factory/registry. */
static const BYTE original[13]={0x39,0xb4,0x24,0xc0,0x05,0x00,0x00,0x0f,0x85,0xf8,0x00,0x00,0x00};
static const BYTE replacement[13]={0x44,0x89,0xbc,0x24,0xc0,0x05,0x00,0x00,0xe9,0xf8,0x00,0x00,0x00};
static const BYTE before[13]={0x41,0xbf,0x01,0x00,0x00,0x00,0x8b,0x84,0x24,0x18,0x01,0x00,0x00};
static const BYTE after[10]={0x8b,0xd0,0x49,0x8b,0xce,0xe8,0xcf,0xb2,0xff,0xff};
static BYTE *site;
__declspec(dllexport) volatile LONG ClassicContextInstalled;
__declspec(dllexport) DWORD WINAPI ClassicContextInitialize(void *unused){
 (void)unused;WCHAR path[32768];HMODULE shell=GetModuleHandleW(L"shell32.dll");
 if(!shell||!GetModuleFileNameW(shell,path,32768))return 1;
 if(!hashMatches(path,"bd11e617c092a82adecad31831389e52226a0b2792e7e3f01e5cee516c7ca4d0"))return 2;
 BYTE *p=(BYTE*)shell+0x2b2362;
 if(ClassicContextInstalled)return site==p&&!memcmp(p,replacement,13)?0:3;
 if(memcmp(p,original,13)||memcmp(p-13,before,13)||memcmp(p+13,after,10))return 4;
 DWORD old;if(!VirtualProtect(p,13,PAGE_EXECUTE_READWRITE,&old))return 5;
 memcpy(p,replacement,13);BOOL flushed=FlushInstructionCache(GetCurrentProcess(),p,13);DWORD ignored;BOOL protected=VirtualProtect(p,13,old,&ignored);
 site=p;InterlockedExchange(&ClassicContextInstalled,1);return flushed&&protected?0:6;
}
__declspec(dllexport) DWORD WINAPI ClassicContextRestore(void *unused){
 (void)unused;if(!ClassicContextInstalled)return 0;
 if(!site||memcmp(site,replacement,13))return 7;
 DWORD old;if(!VirtualProtect(site,13,PAGE_EXECUTE_READWRITE,&old))return 5;
 memcpy(site,original,13);BOOL flushed=FlushInstructionCache(GetCurrentProcess(),site,13);DWORD ignored;BOOL protected=VirtualProtect(site,13,old,&ignored);
 InterlockedExchange(&ClassicContextInstalled,0);return flushed&&protected?0:6;
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved){(void)reserved;if(reason==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(instance);return TRUE;}
