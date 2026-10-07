#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
#include "StartCompatTrace.h"
__declspec(dllexport) START_TRACE_STATE StartCompatTraceState;
typedef void *W10_HSTRING;
typedef HRESULT (WINAPI *PFN_STR)(const wchar_t*,UINT,W10_HSTRING*);
typedef HRESULT (WINAPI *PFN_DEL)(W10_HSTRING);
typedef HRESULT (WINAPI *PFN_ROFACT)(W10_HSTRING,const GUID*,void**);
typedef HRESULT (WINAPI *PFN_DLLFACT)(W10_HSTRING,void**);
typedef HRESULT (WINAPI *PFN_QI)(void*,const GUID*,void**);
typedef ULONG (WINAPI *PFN_RELEASE)(void*);
typedef HRESULT (WINAPI *PFN_GET)(void*,void**);
typedef HRESULT (WINAPI *PFN_LOADPRI)(void*,const wchar_t*);
typedef HRESULT (WINAPI *PFN_CORFACT)(const wchar_t*,const GUID*,void**);
typedef wchar_t** (WINAPI *PFN_ARGS)(int*);
static HMODULE selfModule,corModule,startModule;
static wchar_t directory[32768],iniPath[32768],uiPath[32768],priPath[32768];
static INIT_ONCE pathsOnce=INIT_ONCE_STATIC_INIT,hostOnce=INIT_ONCE_STATIC_INIT;
static const GUID dockedApp={0x4c2caead,0x9da8,0x30ec,{0xb6,0xd3,0xcb,0xd5,0x74,0xed,0xcb,0x35}};
static const GUID oldApp={0x1ecdc9e0,0xbdb1,0x3551,{0x8c,0xee,0x4b,0x77,0x54,0x0c,0x44,0xb3}};
static const GUID dockedMetadata={0xd5783e97,0x0462,0x3a6b,{0xaa,0x60,0x50,0x0d,0xb1,0x1d,0x3e,0xf6}};
static const GUID oldMetadata={0xf2777c41,0xd2cc,0x34b6,{0xa7,0xea,0x19,0xf6,0xc6,0x5f,0x0c,0x19}};
static const GUID resourceStatics={0x4a8eac58,0xb652,0x459d,{0x8d,0xe1,0x23,0x94,0x71,0xe8,0xb2,0x2b}};
static const GUID resourceExtensions={0x8c25e859,0x1042,0x4da0,{0x92,0x32,0xbf,0x2a,0xa8,0xff,0x37,0x26}};
static void trace(const wchar_t *format,...) {wchar_t line[2048];va_list a;va_start(a,format);_vsnwprintf(line,2047,format,a);va_end(a);line[2047]=0;LONG sequence=InterlockedIncrement(&StartCompatTraceState.nextSequence);START_TRACE_ENTRY *entry=&StartCompatTraceState.entries[(unsigned)(sequence-1)%START_TRACE_COUNT];entry->sequence=0;wcsncpy(entry->text,line,START_TRACE_CHARS-1);entry->text[START_TRACE_CHARS-1]=0;InterlockedExchange(&entry->sequence,sequence);OutputDebugStringW(line);}
static void *slot(void *p,int n){return (*(void***)p)[n];}
static void release(void *p){if(p)((PFN_RELEASE)slot(p,2))(p);}
#include "StartExperienceCompat.h"
static BOOL enabled(void){wchar_t flag[8];DWORD n=GetEnvironmentVariableW(L"W10_STARTCOMPAT_ENABLE",flag,8);if(n==1)return flag[0]==L'1';wchar_t path[32768];GetModuleFileNameW(selfModule,path,32768);wchar_t *slash=wcsrchr(path,L'\\');if(!slash)return FALSE;wcscpy(slash+1,L"StartCompat.ini");return GetPrivateProfileIntW(L"Options",L"Enable",0,path)==1;}
static BOOL CALLBACK initPaths(PINIT_ONCE once,void *argument,void **context){
 (void)once;(void)argument;(void)context;
 GetModuleFileNameW(selfModule,directory,32768);wchar_t *slash=wcsrchr(directory,L'\\');if(slash)slash[1]=0;
 swprintf(iniPath,32768,L"%lsStartCompat.ini",directory);
 wchar_t fallback[32768];swprintf(fallback,32768,L"%lsStartUI_.dll",directory);
 GetPrivateProfileStringW(L"Paths",L"StartUI",fallback,uiPath,32768,iniPath);
 swprintf(fallback,32768,L"%lsWindows.UI.ShellCommon.pri",directory);
 GetPrivateProfileStringW(L"Paths",L"ShellCommonPri",fallback,priPath,32768,iniPath);
 swprintf(fallback,32768,L"%lsWinCorHost.dll",directory);
 corModule=LoadLibraryExW(fallback,NULL,LOAD_WITH_ALTERED_SEARCH_PATH);
 trace(L"[StartCompat] Forward module=%p error=%lu",corModule,GetLastError());return TRUE;
}
static void paths(void){InitOnceExecuteOnce(&pathsOnce,initPaths,NULL,NULL);}
static BOOL replaceBytes(void*,const void*,SIZE_T);
#include "CdsBatchedCompat.h"
static BOOL diagnosticTimeouts(void){return GetPrivateProfileIntW(L"Options",L"DiagnosticOrdinaryTimeouts",0,iniPath)!=0;}
static void diagnosticStack(const wchar_t *kind,ULONG_PTR detail){void *frames[32];USHORT n=CaptureStackBackTrace(1,32,frames,NULL);trace(L"[StartCompat] DIAG %ls detail=%llx tick=%llu thread=%lu",kind,(ULONGLONG)detail,GetTickCount64(),GetCurrentThreadId());for(unsigned i=0;i<n;i++)trace(L"[StartCompat] DIAG_STACK %u=%p",i,frames[i]);if(!IsDebuggerPresent())Sleep(200);}
static BOOL WINAPI diagnosticTerminate(HANDLE process,UINT code){diagnosticStack(L"TerminateProcess",code);return TerminateProcess(process,code);}
static void WINAPI diagnosticExit(UINT code){diagnosticStack(L"ExitProcess",code);ExitProcess(code);}
static DWORD WINAPI diagnosticWait(HANDLE object,DWORD milliseconds,BOOL alertable){ULONGLONG start=GetTickCount64();if(milliseconds>=5000)trace(L"[StartCompat] DIAG_WAIT begin object=%p timeout=%lu caller=%p thread=%lu",object,milliseconds,__builtin_return_address(0),GetCurrentThreadId());DWORD result=WaitForSingleObjectEx(object,milliseconds,alertable);if(milliseconds>=5000)trace(L"[StartCompat] DIAG_WAIT end object=%p result=%08lx elapsed=%llu thread=%lu",object,result,GetTickCount64()-start,GetCurrentThreadId());return result;}
static void installDiagnosticImports(HMODULE module){if(!diagnosticTimeouts())return;BYTE *base=(BYTE*)module;IMAGE_NT_HEADERS64 *nt=(IMAGE_NT_HEADERS64*)(base+((IMAGE_DOS_HEADER*)base)->e_lfanew);DWORD rva=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;if(!rva)return;unsigned count=0;for(IMAGE_IMPORT_DESCRIPTOR *d=(IMAGE_IMPORT_DESCRIPTOR*)(base+rva);d->Name;d++){if(!d->OriginalFirstThunk)continue;ULONGLONG *names=(ULONGLONG*)(base+d->OriginalFirstThunk);void **entries=(void**)(base+d->FirstThunk);for(unsigned i=0;names[i];i++){if(names[i]&IMAGE_ORDINAL_FLAG64)continue;char *name=(char*)base+names[i]+2;void *hook=!strcmp(name,"TerminateProcess")?(void*)diagnosticTerminate:!strcmp(name,"ExitProcess")?(void*)diagnosticExit:!strcmp(name,"WaitForSingleObjectEx")?(void*)diagnosticWait:NULL;if(hook&&replaceBytes(entries+i,&hook,sizeof(hook)))count++;}}trace(L"[StartCompat] Diagnostic imports=%u module=%p",count,module);}
static void installOrdinaryTimeouts(HMODULE module){if(!diagnosticTimeouts())return;const DWORD sites[]={0x2715c,0x275a0};const BYTE expected[][6]={{0xff,0x15,0xa6,0x14,0x57,0},{0xff,0x15,0x62,0x10,0x57,0}};const BYTE normal[]={0x31,0xc0,0x90,0x90,0x90,0x90};for(unsigned i=0;i<2;i++)if(memcmp((BYTE*)module+sites[i],expected[i],6)){trace(L"[StartCompat] Ordinary UTM timeouts refused bytes at%u",i);return;}for(unsigned i=0;i<2;i++)trace(L"[StartCompat] Ordinary60sec UTM timeout diagnostic=%d site=%x",replaceBytes((BYTE*)module+sites[i],normal,6),sites[i]);}

static void *(WINAPI *realFrameType)(void*,W10_HSTRING);
static void *WINAPI traceFrameType(void *eventArgs,W10_HSTRING arguments){
 typedef const wchar_t*(WINAPI *GETRAW)(W10_HSTRING,UINT*);GETRAW raw=(GETRAW)GetProcAddress(GetModuleHandleW(L"combase.dll"),"WindowsGetStringRawBuffer");UINT count=0;const wchar_t *text=raw?raw(arguments,&count):L"<raw function unavailable>";trace(L"[StartCompat] GetFrameType argument length=%u value=%ls",count,text?text:L"<NULL>");return realFrameType(eventArgs,arguments);
}
static void installFrameTrace(HMODULE module){
 BYTE *site=(BYTE*)module+0xdaaa1;const BYTE expected[]={0xe8,0xfa,0x15,0,0};if(memcmp(site,expected,5)){trace(L"[StartCompat] Frame trace skipped: callsite does not match");return;}
 SYSTEM_INFO system;GetSystemInfo(&system);ULONG_PTR start=((ULONG_PTR)site)&~((ULONG_PTR)system.dwAllocationGranularity-1);BYTE *thunk=NULL;
 for(ULONG_PTR distance=system.dwAllocationGranularity;distance<0x40000000&&!thunk;distance+=system.dwAllocationGranularity){thunk=VirtualAlloc((void*)(start+distance),4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(!thunk&&start>distance)thunk=VirtualAlloc((void*)(start-distance),4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);}
 if(!thunk)return;BYTE code[14]={0xff,0x25,0,0,0,0};void *hook=traceFrameType;CopyMemory(code+6,&hook,8);CopyMemory(thunk,code,14);DWORD old;VirtualProtect(thunk,4096,PAGE_EXECUTE_READ,&old);FlushInstructionCache(GetCurrentProcess(),thunk,14);
 BYTE call[5]={0xe8};LONG relative=(LONG)(thunk-(site+5));CopyMemory(call+1,&relative,4);realFrameType=(void*)((BYTE*)module+0xdc0a0);trace(L"[StartCompat] GetFrameType diagnostic callsite patch=%d",replaceBytes(site,call,5));
}
static void installTileImageLoadAdapter(HMODULE module){
 // Native ITileImageResource inserted get_UsesTargetSize at slot9. Old LoadAsync is slot10 now.
 // Exact PDBs prove all six prior signatures; old StartUI only calls UnresolvedPath and LoadAsync.
 BYTE *native=(BYTE*)GetModuleHandleW(L"StartTileData.dll");BYTE *site=(BYTE*)module+0x207eb;
 const BYTE expected[]={0x48,0x8b,0x40,0x48,0xff,0x15,0xa3,0x84,0x57,0x00};
 if(!native||memcmp(site,expected,sizeof(expected))||*(void**)(native+0x3f44d0+9*8)!=native+0x149be0||*(void**)(native+0x3f44d0+10*8)!=native+0x2cae10){trace(L"[StartCompat] Tile image LoadAsync adapter refused mismatched ABI");return;}
 BYTE offset=0x50;trace(L"[StartCompat] Tile image LoadAsync slot9 -> slot10 adapter=%d",replaceBytes(site+3,&offset,1));
}
static void installGlobalPropertiesGuid(HMODULE module){
 // Both PDB vtables have identical 26 entries; only the default interface IID changed.
 // Redirect the C++/CX cast while preserving the actual UTM object and native event source.
 const GUID oldId={0xc6da4ccf,0xcc4c,0x410e,{0x99,0x23,0x0a,0x10,0xba,0xf1,0x46,0xb2}};
 const GUID hostId={0xee807266,0xa2db,0x4c9a,{0xa1,0xb4,0x97,0x0d,0x33,0xf9,0x9c,0x91}};
 BYTE *site=(BYTE*)module+0x5c4268;
 if(memcmp(site,&oldId,sizeof(GUID))){trace(L"[StartCompat] Global properties IID patch skipped: GUID does not match");return;}
 trace(L"[StartCompat] Global properties IID adapter=%d",replaceBytes(site,&hostId,sizeof(GUID)));
}
__declspec(dllexport) HRESULT WINAPI StartCompatGetFactory(const wchar_t*,const GUID*,void**);
static void patchStartImports(HMODULE module){
 BYTE *base=(BYTE*)module;IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER*)base;IMAGE_NT_HEADERS64 *nt=(IMAGE_NT_HEADERS64*)(base+dos->e_lfanew);
 DWORD importRva=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;if(!importRva)return;
 IMAGE_IMPORT_DESCRIPTOR *d=(IMAGE_IMPORT_DESCRIPTOR*)(base+importRva);
 for(;d->Name;d++){if(_stricmp((char*)base+d->Name,"wincorlib.dll")||!d->OriginalFirstThunk)continue;
  ULONGLONG *names=(ULONGLONG*)(base+d->OriginalFirstThunk);void **pointers=(void**)(base+d->FirstThunk);
  for(unsigned i=0;names[i];i++){if(names[i]&IMAGE_ORDINAL_FLAG64)continue;const char *name=(char*)base+names[i]+2;
   if(strcmp(name,"?GetActivationFactoryByPCWSTR@@YAJPEAXAEAVGuid@Platform@@PEAPEAX@Z"))continue;
   DWORD old,unused;if(VirtualProtect(&pointers[i],sizeof(void*),PAGE_READWRITE,&old)){pointers[i]=(void*)&StartCompatGetFactory;VirtualProtect(&pointers[i],sizeof(void*),old,&unused);trace(L"[StartCompat] Old StartUI factory import redirected in memory");}
  }
 }
}
static HRESULT loadResources(void){
 paths();HMODULE combase=GetModuleHandleW(L"combase.dll");if(!combase)combase=LoadLibraryW(L"combase.dll");
 PFN_STR create=(PFN_STR)GetProcAddress(combase,"WindowsCreateString");PFN_DEL del=(PFN_DEL)GetProcAddress(combase,"WindowsDeleteString");PFN_ROFACT get=(PFN_ROFACT)GetProcAddress(combase,"RoGetActivationFactory");
 const wchar_t *name=L"Windows.ApplicationModel.Resources.Core.ResourceManager";W10_HSTRING s=NULL;void *factory=NULL,*manager=NULL,*extension=NULL;HRESULT hr=create(name,(UINT)wcslen(name),&s);
 if(FAILED(hr))return hr;
 hr=get(s,&resourceStatics,&factory);del(s);if(FAILED(hr))goto done;
 hr=((PFN_GET)slot(factory,7))(factory,&manager);if(FAILED(hr))goto done;
 hr=((PFN_QI)slot(manager,0))(manager,&resourceExtensions,&extension);if(FAILED(hr))goto done;
 hr=((PFN_LOADPRI)slot(extension,6))(extension,priPath);
done:release(extension);release(manager);release(factory);trace(L"[StartCompat] LoadPriFileForSystemUse=%08lx path=%ls",hr,priPath);return hr;
}
static HRESULT oldFactory(const wchar_t *name,const GUID *iid,void **out){
 paths();*out=NULL;if(!startModule){startModule=LoadLibraryExW(uiPath,NULL,LOAD_WITH_ALTERED_SEARCH_PATH);if(startModule){patchStartImports(startModule);installFrameTrace(startModule);installGlobalPropertiesGuid(startModule);installBatchedAdapter();installTileImageLoadAdapter(startModule);installDiagnosticImports(startModule);installOrdinaryTimeouts(startModule);}}
 if(!startModule)return HRESULT_FROM_WIN32(GetLastError());
 PFN_DLLFACT get=(PFN_DLLFACT)GetProcAddress(startModule,"DllGetActivationFactory");if(!get)return HRESULT_FROM_WIN32(GetLastError());
 HMODULE combase=GetModuleHandleW(L"combase.dll");PFN_STR create=(PFN_STR)GetProcAddress(combase,"WindowsCreateString");PFN_DEL del=(PFN_DEL)GetProcAddress(combase,"WindowsDeleteString");
 W10_HSTRING s=NULL;void *factory=NULL;HRESULT hr=create(name,(UINT)wcslen(name),&s);if(FAILED(hr))return hr;
 hr=get(s,&factory);del(s);if(SUCCEEDED(hr)){hr=((PFN_QI)slot(factory,0))(factory,iid,out);release(factory);}
 trace(L"[StartCompat] Factory %ls=%08lx",name,hr);return hr;
}
static BOOL replaceBytes(void *address,const void *replacement,SIZE_T length){DWORD old,unused;if(!VirtualProtect(address,length,PAGE_EXECUTE_READWRITE,&old))return FALSE;CopyMemory(address,replacement,length);VirtualProtect(address,length,old,&unused);FlushInstructionCache(GetCurrentProcess(),address,length);return TRUE;}
static BOOL CALLBACK patchHost(PINIT_ONCE once,void *argument,void **context){
 (void)once;(void)argument;(void)context;if(!enabled())return TRUE;
 BYTE *base=(BYTE*)GetModuleHandleW(NULL);IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER*)base;if(dos->e_magic!=IMAGE_DOS_SIGNATURE)return TRUE;
 IMAGE_NT_HEADERS64 *nt=(IMAGE_NT_HEADERS64*)(base+dos->e_lfanew);if(nt->Signature!=IMAGE_NT_SIGNATURE)return TRUE;
 wchar_t path[32768];GetModuleFileNameW(NULL,path,32768);wchar_t *name=wcsrchr(path,L'\\');name=name?name+1:path;
 if(_wcsicmp(name,L"StartMenuExperienceHost.exe")){trace(L"[StartCompat] Host patch skipped for %ls",name);return TRUE;}
 IMAGE_SECTION_HEADER *sections=IMAGE_FIRST_SECTION(nt);BYTE *meta=NULL,*experience=NULL;unsigned metaCount=0,experienceCount=0;
 const BYTE pattern[]={0x40,0x53,0x57,0x48,0x83,0xec,0x28,0xe8,0,0,0,0,0x48,0x8b,0xd8,0x48,0x89,0x44,0x24,0x40,0x48,0x8b,0xc8};
 for(unsigned n=0;n<nt->FileHeader.NumberOfSections;n++){
  BYTE *start=base+sections[n].VirtualAddress;DWORD length=sections[n].Misc.VirtualSize;
  if(!memcmp(sections[n].Name,".rdata",6))for(DWORD i=0;i+sizeof(GUID)<=length;i++)if(!memcmp(start+i,&dockedMetadata,sizeof(GUID))){meta=start+i;metaCount++;}
  if(!memcmp(sections[n].Name,".text",5))for(DWORD i=0;i+sizeof(pattern)<=length;i++){BOOL match=TRUE;for(unsigned j=0;j<sizeof(pattern);j++)if((j<8||j>=12)&&start[i+j]!=pattern[j]){match=FALSE;break;}if(match){experience=start+i;experienceCount++;}}
 }
 installDiagnosticImports((HMODULE)base);
 trace(L"[StartCompat] Host metadata matches=%u experience matches=%u",metaCount,experienceCount);
 if(metaCount==1)trace(L"[StartCompat] Host metadata IID patch=%d",replaceBytes(meta,&oldMetadata,sizeof(GUID)));
 // Only an exact unique match is eligible. This follows EP's fix for feature 58205615.
 if(experienceCount==1){BYTE ret=0xc3;trace(L"[StartCompat] Experience-properties patch=%d",replaceBytes(experience,&ret,1));}
 return TRUE;
}
__declspec(dllexport) HRESULT WINAPI StartCompatGetFactory(const wchar_t *name,const GUID *iid,void **out){
 if(!name||!iid||!out)return E_INVALIDARG;paths();
 if(enabled()){
  InitOnceExecuteOnce(&hostOnce,patchHost,NULL,NULL);
  if(!wcscmp(name,L"StartDocked.App")&&IsEqualGUID(iid,&dockedApp)){HRESULT hr=loadResources();if(FAILED(hr))return hr;return oldFactory(L"StartUI.App",&oldApp,out);}
  if(!wcscmp(name,L"StartDocked.startdocked_XamlTypeInfo.XamlMetaDataProvider"))return oldFactory(L"StartUI.startui_XamlTypeInfo.XamlMetaDataProvider",iid,out);
  if(!wcsncmp(name,L"StartUI.",8))return oldFactory(name,iid,out);
 }
 const GUID oldTheme={0xc5f80e59,0xa9fc,0x439d,{0x9f,0xc4,0xd2,0x90,0x85,0x8e,0x18,0x67}};
 const GUID hostTheme={0xc5114793,0xb1f6,0x5005,{0xbd,0x97,0xed,0x6b,0xec,0x1b,0x25,0xf6}};
 const GUID *effectiveIid=iid;
 // Matching old/host PDBs prove all 13 IAppThemeApiStatics vtable signatures identical.
 if(enabled()&&!wcscmp(name,L"ApplicationTheme.AppThemeAPI")&&IsEqualGUID(iid,&oldTheme)){effectiveIid=&hostTheme;trace(L"[StartCompat] AppTheme statics IID adapter");}
 if(!corModule)return E_FAIL;PFN_CORFACT original=(PFN_CORFACT)GetProcAddress(corModule,"?GetActivationFactoryByPCWSTR@@YAJPEAXAEAVGuid@Platform@@PEAPEAX@Z");HRESULT hr=original?original(name,effectiveIid,out):E_NOINTERFACE;
 if(FAILED(hr)||wcsncmp(name,L"Windows.UI.Xaml.",16))trace(L"[StartCompat] Native factory %ls hr=%08lx iid=%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",name,hr,iid->Data1,iid->Data2,iid->Data3,iid->Data4[0],iid->Data4[1],iid->Data4[2],iid->Data4[3],iid->Data4[4],iid->Data4[5],iid->Data4[6],iid->Data4[7]);
 if(enabled()&&!wcscmp(name,L"Windows.Internal.Shell.StartUI.StartExperience")&&IsEqualGUID(iid,&experienceStaticsId)){trace(L"[StartCompat] Native StartExperienceStatics=%08lx",hr);if(SUCCEEDED(hr)&&GetPrivateProfileIntW(L"Options",L"WrapStartExperience",0,iniPath)==1){hr=wrapExperience(out,TRUE);trace(L"[StartCompat] StartExperienceStatics adapter=%08lx",hr);}}
 return hr;
}
__declspec(dllexport) wchar_t** WINAPI StartCompatGetArguments(int *argc){
 paths();if(enabled())InitOnceExecuteOnce(&hostOnce,patchHost,NULL,NULL);
 PFN_ARGS original=corModule?(PFN_ARGS)GetProcAddress(corModule,"?GetCmdArguments@Details@Platform@@YAPEAPEA_WPEAH@Z"):NULL;return original?original(argc):NULL;
}
__declspec(dllexport) HRESULT WINAPI StartCompatLoadResources(void){if(!enabled())return E_ACCESSDENIED;return loadResources();}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,void *reserved){(void)reserved;if(reason==DLL_PROCESS_ATTACH){selfModule=module;DisableThreadLibraryCalls(module);}return TRUE;}
