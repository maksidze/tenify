#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <roapi.h>
#include <winstring.h>
#include <inspectable.h>
#include <appmodel.h>
#include <initializer_list>
#include <wchar.h>
#include <psapi.h>
#include "../Theme10BrowserProbe/HashCheck.hpp"
#include "SelectorPins.h"
using RO=HRESULT(WINAPI*)(HSTRING,REFIID,void**);using PC=HRESULT(WINAPI*)(PCWSTR,REFIID,void**);using FACTORY=HRESULT(WINAPI*)(HSTRING,IActivationFactory**);
static HMODULE modules[3];static FACTORY factories[3];static RO originalRO;static PC originalPC;static bool active,bad;static SRWLOCK gate=SRWLOCK_INIT;
struct SLOT{void**address;void*original;void*replacement;DWORD protection;bool published;};static SLOT slots[8];static int count;
extern "C" __declspec(dllexport) DWORD SettingsFactoryCounters[8]={1,0,0,0,0,0,0,0};

struct TRACE { volatile LONG seq; DWORD tid,route; HRESULT hr; ULONG_PTR caller,vtable; GUID iid; WCHAR name[256]; };
extern "C" __declspec(dllexport) TRACE SettingsDiagRecords[256]={};
extern "C" __declspec(dllexport) DWORD SettingsDiagHeader[4]={16,1,0,256};
static void trace(PCWSTR name,UINT len,REFIID iid,DWORD route,void*caller,HRESULT hr,void**out){
 if(!name||len>=256||!((len>=15&&!wmemcmp(name,L"SystemSettings.",15))||(len>=24&&!wmemcmp(name,L"SystemSettingsThreshold.",24))))return;
 LONG seq=InterlockedIncrement((LONG*)&SettingsDiagHeader[2]);TRACE&r=SettingsDiagRecords[((UINT)seq-1)&255];InterlockedExchange(&r.seq,0);
 r.tid=GetCurrentThreadId();r.route=route;r.hr=hr;r.caller=(ULONG_PTR)caller;r.vtable=SUCCEEDED(hr)&&out&&*out?(ULONG_PTR)*(void**)*out:0;r.iid=iid;
 wmemcpy(r.name,name,len);r.name[len]=0;InterlockedExchange(&r.seq,seq);
}

static bool physical(HMODULE h,PCWSTR p){WCHAR actual[32768],wanted[32768];DWORD a=K32GetMappedFileNameW(GetCurrentProcess(),h,actual,32768);if(!a||a>=32768)return false;HANDLE f=CreateFileW(p,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);if(f==INVALID_HANDLE_VALUE)return false;DWORD n=GetFinalPathNameByHandleW(f,wanted,32768,VOLUME_NAME_NT);CloseHandle(f);return n&&n<32768&&!_wcsicmp(actual,wanted);}
static bool scoped(PCWSTR name,UINT n){if(n>1024||!name||wmemchr(name,0,n))return false;for(auto excluded:{L"SystemSettings.DataModel.",L"SystemSettings.Handlers."}){size_t k=wcslen(excluded);if(n>=k&&!wmemcmp(name,excluded,k))return false;}for(auto prefix:{L"SystemSettings.",L"SystemSettingsThreshold."}){size_t k=wcslen(prefix);if(n>=k&&!wmemcmp(name,prefix,k))return true;}return false;}
static HRESULT choose(HSTRING name,REFIID iid,void**out){if(!out)return E_POINTER;*out=nullptr;for(int i:{1,2,0}){IActivationFactory*f=nullptr;HRESULT hr=factories[i](name,&f);if(SUCCEEDED(hr)&&f){hr=f->QueryInterface(iid,out);f->Release();InterlockedIncrement((LONG*)&SettingsFactoryCounters[2+i]);if(FAILED(hr))InterlockedIncrement((LONG*)&SettingsFactoryCounters[6]);return hr;}if(f)f->Release();if(hr!=CLASS_E_CLASSNOTAVAILABLE&&hr!=REGDB_E_CLASSNOTREG)return SUCCEEDED(hr)?E_UNEXPECTED:hr;}InterlockedIncrement((LONG*)&SettingsFactoryCounters[5]);return originalRO(name,iid,out);}
static HRESULT WINAPI hookRO(HSTRING name,REFIID iid,void**out){UINT n=0;PCWSTR p=WindowsGetStringRawBuffer(name,&n);bool use;AcquireSRWLockShared(&gate);use=active&&scoped(p,n);ReleaseSRWLockShared(&gate);HRESULT hr;if(use)hr=choose(name,iid,out);else{InterlockedIncrement((LONG*)&SettingsFactoryCounters[1]);hr=originalRO(name,iid,out);}trace(p,n,iid,use?1:0,__builtin_return_address(0),hr,out);return hr;}
static HRESULT WINAPI hookPC(PCWSTR name,REFIID iid,void**out){if(!name)return E_INVALIDARG;UINT n=(UINT)wcslen(name);bool use;AcquireSRWLockShared(&gate);use=active&&scoped(name,n);ReleaseSRWLockShared(&gate);if(!use){InterlockedIncrement((LONG*)&SettingsFactoryCounters[1]);return originalPC(name,iid,out);}HSTRING s=nullptr;HRESULT hr=WindowsCreateString(name,n,&s);if(SUCCEEDED(hr)){hr=choose(s,iid,out);trace(name,n,iid,2,__builtin_return_address(0),hr,out);WindowsDeleteString(s);}return hr;}
static DWORD init(bool fixture){AcquireSRWLockExclusive(&gate);DWORD result=0;if(bad){result=ERROR_INVALID_STATE;goto end;}if(active){for(int i=0;i<count;i++)if(*slots[i].address!=slots[i].replacement)result=ERROR_BUSY;goto end;}{WCHAR path[32768];if(!GetModuleFileNameW(nullptr,path,32768)||!physical(GetModuleHandleW(nullptr),path)||_wcsicmp(path,fixture?OWN_EXE_PATH:NATIVE_EXE_PATH)||!hashMatches(path,fixture?OWN_EXE_SHA:NATIVE_EXE_SHA)){result=ERROR_ACCESS_DENIED;goto end;}UINT n=1024;WCHAR family[1024];if(GetCurrentPackageFamilyName(&n,family)||wcscmp(family,L"windows.immersivecontrolpanel_cw5n1h2txyewy")){result=ERROR_ACCESS_DENIED;goto end;}}
 {HRESULT hr=RoInitialize(RO_INIT_MULTITHREADED);if(FAILED(hr)&&hr!=RPC_E_CHANGED_MODE){result=hr;goto end;}}
 for(int i=0;i<3;i++){if(!hashMatches(modulePins[i].path,modulePins[i].sha)){result=ERROR_REVISION_MISMATCH;goto end;}modules[i]=LoadLibraryExW(modulePins[i].path,nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if(!modules[i]||!physical(modules[i],modulePins[i].path)){result=ERROR_REVISION_MISMATCH;goto end;}factories[i]=(FACTORY)GetProcAddress(modules[i],"DllGetActivationFactory");if(!factories[i]){result=ERROR_PROC_NOT_FOUND;goto end;}}
 originalRO=(RO)GetProcAddress(GetModuleHandleW(L"combase.dll"),"RoGetActivationFactory");originalPC=(PC)GetProcAddress(GetModuleHandleW(L"wincorlib.dll"),"?GetActivationFactoryByPCWSTR@@YAJPEAXAEAVGuid@Platform@@PEAPEAX@Z");if(!originalRO||!originalPC){result=ERROR_PROC_NOT_FOUND;goto end;}
 count=0;
 for(int i=0;i<3;i++){const DWORD rvas[]={modulePins[i].ro,modulePins[i].pc};for(int kind=0;kind<2;kind++){if(!rvas[kind])continue;SLOT&r=slots[count++];r.address=(void**)((BYTE*)modules[i]+rvas[kind]);r.original=kind?(void*)originalPC:(void*)originalRO;r.replacement=kind?(void*)hookPC:(void*)hookRO;if(*r.address!=r.original){result=ERROR_BUSY;goto end;}}}
 {HMODULE exe=GetModuleHandleW(nullptr);auto nt=(IMAGE_NT_HEADERS64*)((BYTE*)exe+((IMAGE_DOS_HEADER*)exe)->e_lfanew);auto desc=(IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)exe+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);for(;desc->Name;desc++){if(!desc->OriginalFirstThunk)continue;auto names=(IMAGE_THUNK_DATA64*)((BYTE*)exe+desc->OriginalFirstThunk);auto ptrs=(IMAGE_THUNK_DATA64*)((BYTE*)exe+desc->FirstThunk);for(;names->u1.AddressOfData;names++,ptrs++){if(IMAGE_SNAP_BY_ORDINAL64(names->u1.Ordinal))continue;auto name=(IMAGE_IMPORT_BY_NAME*)((BYTE*)exe+names->u1.AddressOfData);if(!strcmp((char*)name->Name,"RoGetActivationFactory")){if(count>=8){result=ERROR_BUFFER_OVERFLOW;goto end;}SLOT&r=slots[count++];r.address=(void**)&ptrs->u1.Function;r.original=(void*)originalRO;r.replacement=(void*)hookRO;if(*r.address!=r.original){result=ERROR_BUSY;goto end;}}}}}
 {HMODULE pin;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(PCWSTR)&init,&pin)){result=GetLastError();goto end;}for(auto h:modules)if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(PCWSTR)h,&pin)){result=GetLastError();goto end;}}
 for(int i=0;i<count;i++){SLOT&r=slots[i];DWORD tmp;if(!VirtualProtect(r.address,8,PAGE_READWRITE,&r.protection)){result=GetLastError();bad=true;goto end;}void*previous=InterlockedCompareExchangePointer(r.address,r.replacement,r.original);r.published=previous==r.original;BOOL protectedAgain=VirtualProtect(r.address,8,r.protection,&tmp);if(!r.published||!protectedAgain||*r.address!=r.replacement){result=ERROR_WRITE_FAULT;bad=true;goto end;}}active=true;SettingsFactoryCounters[7]=count;
end:ReleaseSRWLockExclusive(&gate);return result;}

static const GUID diagInspectableIID={0xaf86e2e0,0xb12d,0x4c6a,{0x9c,0x5a,0xd7,0xaa,0x65,0x10,0x1e,0x90}};
static const GUID ownActivationFactoryIID={0x35,0,0,{0xc0,0,0,0,0,0,0,0x46}};
using RA=HRESULT(WINAPI*)(HSTRING,IInspectable**);static RA originalRA;static bool diagnosticInstalled;
static HRESULT WINAPI dataRO(HSTRING s,REFIID i,void**o){UINT n;PCWSTR p=WindowsGetStringRawBuffer(s,&n);HRESULT h=originalRO(s,i,o);trace(p,n,i,3,__builtin_return_address(0),h,o);return h;}
static HRESULT WINAPI xamlRO(HSTRING s,REFIID i,void**o){UINT n;PCWSTR p=WindowsGetStringRawBuffer(s,&n);HRESULT h=scoped(p,n)?choose(s,i,o):originalRO(s,i,o);trace(p,n,i,8,__builtin_return_address(0),h,o);return h;}
static HRESULT WINAPI dataRA(HSTRING s,IInspectable**o){UINT n;PCWSTR p=WindowsGetStringRawBuffer(s,&n);HRESULT h=originalRA(s,o);trace(p,n,diagInspectableIID,5,__builtin_return_address(0),h,(void**)o);return h;}
static HRESULT WINAPI xamlRA(HSTRING s,IInspectable**o){UINT n;PCWSTR p=WindowsGetStringRawBuffer(s,&n);HRESULT h;if(scoped(p,n)){IActivationFactory*f=nullptr;h=choose(s,ownActivationFactoryIID,(void**)&f);if(SUCCEEDED(h)){if(!f)h=E_UNEXPECTED;else{h=f->ActivateInstance(o);f->Release();}}}else h=originalRA(s,o);trace(p,n,diagInspectableIID,9,__builtin_return_address(0),h,(void**)o);return h;}
static HRESULT WINAPI oldMainRA(HSTRING s,IInspectable**o){UINT n;PCWSTR p=WindowsGetStringRawBuffer(s,&n);HRESULT h=originalRA(s,o);trace(p,n,diagInspectableIID,7,__builtin_return_address(0),h,(void**)o);return h;}
struct DP{PCWSTR path;const char*sha;DWORD ro,ra;void*roHook;void*raHook;};
static DWORD diagnosticInit(){
 if(diagnosticInstalled)return ERROR_ALREADY_INITIALIZED;
 originalRA=(RA)GetProcAddress(GetModuleHandleW(L"combase.dll"),"RoActivateInstance");if(!originalRA)return ERROR_PROC_NOT_FOUND;
 DP pins[]={
 {L"C:\\Windows\\System32\\SystemSettings.DataModel.dll","f07bdc1334562d4ae3d5265e96cf44b8bfbde8388fd71e76cb698cc475703fbb",0x103120,0x103128,(void*)dataRO,(void*)dataRA},
 {L"C:\\Windows\\System32\\Windows.UI.Xaml.dll","7a2fb4f7933a8d74708a4b78085b7c67332fafcc9cd5c3d2d240bff404c4b544",0x105e448,0x105e438,(void*)xamlRO,(void*)xamlRA},
 {modulePins[0].path,modulePins[0].sha,0,0x46d648,nullptr,(void*)oldMainRA}};
 struct CELL{void**p;void*old;void*hook;};CELL cells[6];int used=0;
 for(auto&pin:pins){if(!hashMatches(pin.path,pin.sha))return ERROR_REVISION_MISMATCH;HMODULE m=LoadLibraryExW(pin.path,0,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if(!m||!physical(m,pin.path))return ERROR_REVISION_MISMATCH;
 HANDLE file=CreateFileW(pin.path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,0,OPEN_EXISTING,0,0);if(file==INVALID_HANDLE_VALUE)return GetLastError();HANDLE mapping=CreateFileMappingW(file,0,PAGE_READONLY,0,0,0);CloseHandle(file);if(!mapping)return GetLastError();BYTE*raw=(BYTE*)MapViewOfFile(mapping,FILE_MAP_READ,0,0,0);if(!raw){CloseHandle(mapping);return GetLastError();}
 auto nt=(IMAGE_NT_HEADERS64*)(raw+((IMAGE_DOS_HEADER*)raw)->e_lfanew);auto sections=IMAGE_FIRST_SECTION(nt);
 for(int k=0;k<2;k++){DWORD rva=k?pin.ra:pin.ro;if(!rva)continue;ULONGLONG disk=0;bool found=false;for(int s=0;s<nt->FileHeader.NumberOfSections;s++)if(rva>=sections[s].VirtualAddress&&rva+8<=sections[s].VirtualAddress+sections[s].SizeOfRawData){memcpy(&disk,raw+sections[s].PointerToRawData+rva-sections[s].VirtualAddress,8);found=true;break;}
 void**address=(void**)((BYTE*)m+rva);void*current=*address;void*native=k?(void*)originalRA:(void*)originalRO;void*relocated=disk>nt->OptionalHeader.ImageBase&&disk<nt->OptionalHeader.ImageBase+nt->OptionalHeader.SizeOfImage?(BYTE*)m+(disk-nt->OptionalHeader.ImageBase):nullptr;
 if(!found||(current!=native&&(!relocated||current!=relocated))){UnmapViewOfFile(raw);CloseHandle(mapping);return ERROR_BUSY;}cells[used++]={address,current,k?pin.raHook:pin.roHook};}
 UnmapViewOfFile(raw);CloseHandle(mapping);}
 for(int i=0;i<used;i++){auto&c=cells[i];DWORD old,tmp;if(!VirtualProtect(c.p,8,PAGE_READWRITE,&old))return GetLastError();void*v=InterlockedCompareExchangePointer(c.p,c.hook,c.old);BOOL ok=VirtualProtect(c.p,8,old,&tmp);if(v!=c.old||!ok||*c.p!=c.hook)return ERROR_WRITE_FAULT;}
 diagnosticInstalled=true;return 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI SettingsNoVfsInitialize(void*){DWORD r=init(false);return r?r:diagnosticInit();}
extern "C" __declspec(dllexport) DWORD WINAPI SettingsNoVfsFixtureInitialize(void*){DWORD r=init(true);return r?r:diagnosticInit();}
// No hot restoration after WinRT factory caching. Exact own process teardown releases state.
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,void*){if(r==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(h);return TRUE;}
