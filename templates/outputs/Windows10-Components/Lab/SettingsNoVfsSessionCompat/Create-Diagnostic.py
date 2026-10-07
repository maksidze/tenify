from pathlib import Path
import shutil,hashlib,json,sys,subprocess
L=Path(__file__).resolve().parent;H=L.parent/'SettingsNoVfsCompat';D=L.parent/'SettingsNoVfsDiagnostics';D.mkdir(exist_ok=True)
for n in ['SelectorPins.h']:(D/n).write_bytes((H/n).read_bytes())
t=(H/'SettingsFactorySelector.cpp').read_text()
declaration=r'''
struct TRACE { volatile LONG seq; DWORD tid,route; HRESULT hr; ULONG_PTR caller,vtable; GUID iid; WCHAR name[256]; };
extern "C" __declspec(dllexport) TRACE SettingsDiagRecords[256]={};
extern "C" __declspec(dllexport) DWORD SettingsDiagHeader[4]={16,1,0,256};
static void trace(PCWSTR name,UINT len,REFIID iid,DWORD route,void*caller,HRESULT hr,void**out){
 if(!name||len>=256||!((len>=15&&!wmemcmp(name,L"SystemSettings.",15))||(len>=24&&!wmemcmp(name,L"SystemSettingsThreshold.",24))))return;
 LONG seq=InterlockedIncrement((LONG*)&SettingsDiagHeader[2]);TRACE&r=SettingsDiagRecords[((UINT)seq-1)&255];InterlockedExchange(&r.seq,0);
 r.tid=GetCurrentThreadId();r.route=route;r.hr=hr;r.caller=(ULONG_PTR)caller;r.vtable=SUCCEEDED(hr)&&out&&*out?(ULONG_PTR)*(void**)*out:0;r.iid=iid;
 wmemcpy(r.name,name,len);r.name[len]=0;InterlockedExchange(&r.seq,seq);
}
'''
t=t.replace('static bool physical(',declaration+'\nstatic bool physical(')
t=t.replace('if(use)return choose(name,iid,out);InterlockedIncrement((LONG*)&SettingsFactoryCounters[1]);return originalRO(name,iid,out);','HRESULT hr;if(use)hr=choose(name,iid,out);else{InterlockedIncrement((LONG*)&SettingsFactoryCounters[1]);hr=originalRO(name,iid,out);}trace(p,n,iid,use?1:0,__builtin_return_address(0),hr,out);return hr;')
t=t.replace('HRESULT hr=choose(s,iid,out);','HRESULT hr=choose(s,iid,out);')
# Both original source paths have PCWSTR success wrapped after choose.
t=t.replace('hr=choose(s,iid,out);WindowsDeleteString(s);','hr=choose(s,iid,out);trace(name,n,iid,2,__builtin_return_address(0),hr,out);WindowsDeleteString(s);')
extra=r'''
static const GUID diagInspectableIID={0xaf86e2e0,0xb12d,0x4c6a,{0x9c,0x5a,0xd7,0xaa,0x65,0x10,0x1e,0x90}};
using RA=HRESULT(WINAPI*)(HSTRING,IInspectable**);static RA originalRA;static bool diagnosticInstalled;
static HRESULT WINAPI dataRO(HSTRING s,REFIID i,void**o){UINT n;PCWSTR p=WindowsGetStringRawBuffer(s,&n);HRESULT h=originalRO(s,i,o);trace(p,n,i,3,__builtin_return_address(0),h,o);return h;}
static HRESULT WINAPI xamlRO(HSTRING s,REFIID i,void**o){UINT n;PCWSTR p=WindowsGetStringRawBuffer(s,&n);HRESULT h=originalRO(s,i,o);trace(p,n,i,4,__builtin_return_address(0),h,o);return h;}
static HRESULT WINAPI dataRA(HSTRING s,IInspectable**o){UINT n;PCWSTR p=WindowsGetStringRawBuffer(s,&n);HRESULT h=originalRA(s,o);trace(p,n,diagInspectableIID,5,__builtin_return_address(0),h,(void**)o);return h;}
static HRESULT WINAPI xamlRA(HSTRING s,IInspectable**o){UINT n;PCWSTR p=WindowsGetStringRawBuffer(s,&n);HRESULT h=originalRA(s,o);trace(p,n,diagInspectableIID,6,__builtin_return_address(0),h,(void**)o);return h;}
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
'''
t=t.replace('extern "C" __declspec(dllexport) DWORD WINAPI SettingsNoVfsInitialize',extra+'\nextern "C" __declspec(dllexport) DWORD WINAPI SettingsNoVfsInitialize')
t=t.replace('return init(false);','DWORD r=init(false);return r?r:diagnosticInit();').replace('return init(true);','DWORD r=init(true);return r?r:diagnosticInit();')
(D/'SettingsFactorySelectorDiag.cpp').write_text(t)
z=L.parents[3]/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
libs=['-lole32','-lapi-ms-win-core-winrt-l1-1-0','-lapi-ms-win-core-winrt-string-l1-1-0','-lshell32','-luser32','-lbcrypt','-lpsapi','-luuid']
p=subprocess.run([str(z),'c++','-target','x86_64-windows-gnu','-O2','-std=c++17',str(D/'SettingsFactorySelectorDiag.cpp'),'-o',str(D/'SettingsFactorySelectorDiag.dll'),'-shared',*libs],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=60);(D/'build.log').write_bytes(p.stdout+p.stderr)
if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
m=json.loads((H/'adapter-metadata.json').read_text());m['Selector']=str(D/'SettingsFactorySelectorDiag.dll');m['SelectorSHA256']=hashlib.sha256(Path(m['Selector']).read_bytes()).hexdigest();m['Files']+= [dict(Path=str(D/'SettingsFactorySelectorDiag.cpp'),SHA256=hashlib.sha256((D/'SettingsFactorySelectorDiag.cpp').read_bytes()).hexdigest()),dict(Path=m['Selector'],SHA256=m['SelectorSHA256'])];(D/'adapter-metadata.json').write_text(json.dumps(m,indent=2))

