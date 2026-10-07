from pathlib import Path
import hashlib,sys,struct,subprocess,json
lab=Path(__file__).resolve().parent;root=lab.parents[3];sys.path.insert(0,str(root/'work/pylib'));import pefile
vm=root/'outputs/Windows10-Components/Image/4/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll';provider=root/'outputs/Windows10-Components/Image/4/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll';pe=pefile.PE(str(vm))
prior=(root/'outputs/Windows10-Components/Lab/SettingsCaptionCompat/SettingsCaptionCompat.c').read_text();hashfn=prior[prior.index('static BOOL hashMatches'):prior.index('static BOOL sibling')];identity=prior[prior.index('static BOOL loadedAt'):prior.index('/* Read-only identity fixture')]
guards=[]
for rva,target in [(0x240ae,0x17d14),(0x243ad,0x17d14),(0x24513,0x60c4),(0x24834,0x60c4)]:
 b=pe.get_data(rva,5);assert b==b'\xe8'+struct.pack('<i',target-rva-5);guards.append('{0x%x,{%s}}'%(rva,','.join(hex(x) for x in b)))
header='#define UNICODE\n#define _UNICODE\n#include <windows.h>\n#include <objbase.h>\n#include <winstring.h>\n#include <bcrypt.h>\n#include <psapi.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <wchar.h>\n#include <limits.h>\n'
source=header+hashfn+identity+f'''\nstatic const WCHAR vmPath[]=L"{str(vm).replace(chr(92),chr(92)*2)}";
static const WCHAR providerPath[]=L"{str(provider).replace(chr(92),chr(92)*2)}";
static const char vmHash[]="{hashlib.sha256(vm.read_bytes()).hexdigest()}";
static const char providerHash[]="{hashlib.sha256(provider.read_bytes()).hexdigest()}";
typedef struct {{DWORD rva;BYTE original[5],patched[5];}} CallGuard;
static CallGuard guards[4]={{{','.join(guards)}}};
'''+r'''
typedef HRESULT(WINAPI *NativeGet)(void*,HSTRING,void**);
typedef HRESULT(WINAPI *NativeUserGet)(void*,void*,HSTRING,void**);
typedef HRESULT(WINAPI *ProviderGet)(HSTRING,void**);
typedef void*(WINAPI *Projection)(void*,HSTRING);
typedef void*(WINAPI *UserProjection)(void*,void*,HSTRING);
static HMODULE vm,provider;static ProviderGet providerGet;static BYTE*thunks;static SRWLOCK lock=SRWLOCK_INIT;
__declspec(dllexport) volatile LONG PowerInstalled,PowerFallbackCalls,PowerNativeCalls;
__declspec(dllexport) volatile HRESULT PowerLastResult;
static PCWSTR keys[]={L"SystemSettings_PowerAndSleep_DisplayOffTimeoutAC",L"SystemSettings_PowerAndSleep_DisplayOffTimeoutDC",L"SystemSettings_PowerAndSleep_SleepTimeoutAC",L"SystemSettings_PowerAndSleep_SleepTimeoutDC"};
static BOOL exact(HSTRING key){UINT32 count=0;PCWSTR(WINAPI*raw)(HSTRING,UINT32*)=(void*)GetProcAddress(GetModuleHandleW(L"combase.dll"),"WindowsGetStringRawBuffer");if(!raw)return FALSE;PCWSTR text=raw(key,&count);for(int i=0;i<4;i++)if(count==wcslen(keys[i])&&!wmemcmp(text,keys[i],count))return TRUE;return FALSE;}
static void release(void*p){if(p)((ULONG(WINAPI*)(void*))(*(void***)p)[2])(p);}
static HRESULT fallback(HSTRING key,void**out){HRESULT hr=providerGet(key,out);if(FAILED(hr)){release(*out);*out=NULL;}else{
 static const GUID iid={0x40c037cc,0xd8bf,0x489e,{0x86,0x97,0xd6,0x6b,0xaa,0x32,0x21,0xbf}};void*q=NULL;
 if(!*out)return E_UNEXPECTED;hr=((HRESULT(WINAPI*)(void*,REFIID,void**))(*(void***)*out)[0])(*out,&iid,&q);release(q);
 if(FAILED(hr)){release(*out);*out=NULL;}}
 InterlockedIncrement(&PowerFallbackCalls);return hr;}
__declspec(dllexport) HRESULT WINAPI SettingsPowerQuery(void*db,HSTRING key,void**out){
 if(!db||!out)return E_POINTER;*out=NULL;HRESULT hr=((NativeGet)(*(void***)db)[6])(db,key,out);InterlockedIncrement(&PowerNativeCalls);
 if(hr==HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)&&exact(key)){release(*out);*out=NULL;if(!providerGet)return E_UNEXPECTED;hr=fallback(key,out);}PowerLastResult=hr;return hr;}
__declspec(dllexport) HRESULT WINAPI SettingsPowerQueryForUser(void*db,void*user,HSTRING key,void**out){
 if(!db||!out)return E_POINTER;*out=NULL;HRESULT hr=((NativeUserGet)(*(void***)db)[6])(db,user,key,out);InterlockedIncrement(&PowerNativeCalls);
 if(hr==HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)&&exact(key)){release(*out);*out=NULL;if(!providerGet)return E_UNEXPECTED;hr=fallback(key,out);}PowerLastResult=hr;return hr;}
__declspec(dllexport) void*WINAPI SettingsPowerProject(void*db,HSTRING key){
 if(!exact(key))return ((Projection)((BYTE*)vm+0x17d14))(db,key);void*out=NULL;HRESULT hr=SettingsPowerQuery(db,key,&out);
 if(FAILED(hr)){release(out);((void(WINAPI*)(HRESULT))((BYTE*)vm+0x100f8))(hr);return NULL;}return out;}
__declspec(dllexport) void*WINAPI SettingsPowerProjectForUser(void*db,void*user,HSTRING key){
 if(!exact(key))return ((UserProjection)((BYTE*)vm+0x60c4))(db,user,key);void*out=NULL;HRESULT hr=SettingsPowerQueryForUser(db,user,key,&out);
 if(FAILED(hr)){release(out);((void(WINAPI*)(HRESULT))((BYTE*)vm+0x100f8))(hr);return NULL;}return out;}
__declspec(dllexport) DWORD WINAPI SettingsPowerPrepare(void*unused){
 (void)unused;if(providerGet)return 0;if(!hashMatches(providerPath,providerHash))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 provider=LoadLibraryExW(providerPath,NULL,LOAD_WITH_ALTERED_SEARCH_PATH);if(!provider||!loadedAt(provider,providerPath))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 providerGet=(ProviderGet)GetProcAddress(provider,"GetSetting");return providerGet?0:E_NOINTERFACE;}
static BOOL write(void*at,const BYTE*bytes,SIZE_T size){DWORD old,ignored;if(!VirtualProtect(at,size,PAGE_EXECUTE_READWRITE,&old))return FALSE;memcpy(at,bytes,size);FlushInstructionCache(GetCurrentProcess(),at,size);return VirtualProtect(at,size,old,&ignored);}
__declspec(dllexport) DWORD WINAPI SettingsPowerInitialize(void*unused){
 AcquireSRWLockExclusive(&lock);DWORD hr=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);if(PowerInstalled){hr=0;goto end;}
 hr=SettingsPowerPrepare(unused);if(hr)goto end;hr=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);vm=GetModuleHandleW(L"SystemSettingsViewModel.Desktop.dll");
 if(!vm||!hashMatches(vmPath,vmHash)||!loadedAt(vm,vmPath))goto end;
 for(int i=0;i<4;i++)if(memcmp((BYTE*)vm+guards[i].rva,guards[i].original,5))goto end;
 SYSTEM_INFO info;GetSystemInfo(&info);ULONGLONG start=((ULONGLONG)vm+0x100000+info.dwAllocationGranularity-1)&~((ULONGLONG)info.dwAllocationGranularity-1);
 for(ULONGLONG at=start;at<(ULONGLONG)vm+0x70000000;at+=info.dwAllocationGranularity){thunks=VirtualAlloc((void*)at,32,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(thunks)break;}
 if(!thunks){hr=E_OUTOFMEMORY;goto end;}
 for(int n=0;n<2;n++){BYTE*b=thunks+16*n;b[0]=0xff;b[1]=0x25;memset(b+2,0,4);void*fn=n?(void*)SettingsPowerProjectForUser:(void*)SettingsPowerProject;memcpy(b+6,&fn,8);}
 DWORD old;if(!VirtualProtect(thunks,32,PAGE_EXECUTE_READ,&old)){hr=HRESULT_FROM_WIN32(GetLastError());goto end;}FlushInstructionCache(GetCurrentProcess(),thunks,32);
 for(int i=0;i<4;i++){BYTE*at=(BYTE*)vm+guards[i].rva;LONGLONG distance=(thunks+(i>=2?16:0))-(at+5);if(distance<INT_MIN||distance>INT_MAX){hr=E_FAIL;goto end;}guards[i].patched[0]=0xe8;INT32 relative=(INT32)distance;memcpy(guards[i].patched+1,&relative,4);}
 for(int i=0;i<4;i++)if(!write((BYTE*)vm+guards[i].rva,guards[i].patched,5)){hr=HRESULT_FROM_WIN32(GetLastError());for(int j=0;j<=i;j++)write((BYTE*)vm+guards[j].rva,guards[j].original,5);goto end;}
 PowerInstalled=1;hr=0;
 end:PowerLastResult=hr;ReleaseSRWLockExclusive(&lock);return hr;}
__declspec(dllexport) DWORD WINAPI SettingsPowerRestore(void*unused){
 (void)unused;AcquireSRWLockExclusive(&lock);DWORD hr=0;if(PowerInstalled){for(int i=0;i<4;i++)if(memcmp((BYTE*)vm+guards[i].rva,guards[i].patched,5)){hr=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);goto end;}
 for(int i=0;i<4;i++)if(!write((BYTE*)vm+guards[i].rva,guards[i].original,5)){hr=HRESULT_FROM_WIN32(GetLastError());goto end;}PowerInstalled=0;}
 end:ReleaseSRWLockExclusive(&lock);return hr;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD why,LPVOID reserved){(void)reserved;if(why==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(h);return TRUE;}
'''
(lab/'SettingsPowerCompat.c').write_text(source,encoding='utf8');zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe';p=subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-shared','-O2',str(lab/'SettingsPowerCompat.c'),'-o',str(lab/'SettingsPowerCompat.dll'),'-lole32','-lbcrypt','-lpsapi'],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=60);(lab/'adapter-build.log').write_bytes(p.stdout+p.stderr);print('build',p.returncode);print(p.stderr.decode(errors='replace')[:1200]);
if p.returncode:raise SystemExit(p.returncode)
(lab/'adapter-manifest.json').write_text(json.dumps({'vmPath':str(vm),'vmHash':hashlib.sha256(vm.read_bytes()).hexdigest(),'oldProviderPath':str(provider),'oldProviderHash':hashlib.sha256(provider.read_bytes()).hexdigest(),'helperSHA256':hashlib.sha256((lab/'SettingsPowerCompat.dll').read_bytes()).hexdigest(),'callsiteRVAs':['240ae','243ad','24513','24834'],'UITrialPerformed':False,'settersCalled':False},indent=2))
