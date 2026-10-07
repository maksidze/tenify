// Exact native ILauncherTipContextMenu slot adapter. No file/registry patching.
#include "WinXAbi.h"
#include "Guards.h"
#include <bcrypt.h>
#include <psapi.h>
#include <string.h>
#include <new>
#include <stdint.h>
#include "OwnerWindow.h"

extern "C" __declspec(dllexport) struct WinXStats {
 DWORD version=1, installed=0, installError=0, calls=0;
 DWORD completed=0, timeouts=0, menusBuilt=0, lastItemCount=0;
 DWORD selected=0, invoked=0, lastError=0, busy=0;
 DWORD callerThread=0, apartment=0, hotkeyCalls=0,hotkeyInstalled=0;
 UINT64 slotAddress=0, original=0, replacement=0;
} WinXCompatStats={};
static BYTE* pcsBase;
static BYTE* twinuiBase;
static BYTE* hotkeyBridge;
static BYTE hotkeyCall[5];
extern "C" __declspec(dllexport) UINT64 WinXHotkeyPointers[3]={}; // base, callsite, bridge
extern "C" __declspec(dllexport) DWORD WinXHotkeyTrace[8]={}; // tid, apt, qualifier, aptHR, desktop, stage, hr, reserved
extern "C" __declspec(dllexport) UINT64 WinXOwnerTrace[6]={}; // hwnd, callerTid, ownerTid, creationError, popupError, popupMilliseconds
extern "C" __declspec(dllexport) DWORD WinXQueryTrace[8]={}; // budgetMs,elapsedMs,status,statusHr,operationError,waitHr,cancelHr,reserved
extern "C" __declspec(dllexport) UINT64 WinXFocusTrace[3]={}; // foregroundBefore, SetForegroundWindow BOOL, foregroundAfter
static bool WINAPI hotkey();
static volatile LONG showBusy;
static HRESULT STDMETHODCALLTYPE show(Tip*,POINT*);
static const DWORD methodRvas[5]={0x5de1d0,0x44d560,0x5de3e0,0x241ef0,0x5dd0b0};
static HRESULT last(HRESULT h){WinXCompatStats.lastError=h;return h;}

static bool fileHash(const wchar_t* path,const BYTE expected[32]){
 HANDLE f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(f==INVALID_HANDLE_VALUE)return false;
 BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;BYTE bytes[65536],digest[32];DWORD n=0;bool okay=false;
 if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0 && BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0)>=0){
  bool read=true;while((read=ReadFile(f,bytes,sizeof(bytes),&n,nullptr))&&n)if(BCryptHashData(hash,bytes,n,0)<0){read=false;break;}
  okay=read && BCryptFinishHash(hash,digest,sizeof(digest),0)>=0 && !memcmp(digest,expected,32);
 }
 if(hash)BCryptDestroyHash(hash);if(alg)BCryptCloseAlgorithmProvider(alg,0);CloseHandle(f);return okay;
}
static bool mappedAt(HMODULE m,const wchar_t* canonical){
 wchar_t actual[32768],expected[32768];DWORD n=GetMappedFileNameW(GetCurrentProcess(),m,actual,32768);
 if(!n||n>=32768)return false;
 HANDLE h=CreateFileW(canonical,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);if(h==INVALID_HANDLE_VALUE)return false;
 DWORD k=GetFinalPathNameByHandleW(h,expected,32768,VOLUME_NAME_NT);CloseHandle(h);
 return k&&k<32768&&!_wcsicmp(actual,expected);
}
static bool codeGuards(BYTE* base){return !memcmp(base+0x241ef0,Guard0,sizeof(Guard0))&&!memcmp(base+0x5dd0b0,Guard1,sizeof(Guard1))&&!memcmp(base+0x7a86c8,Guard2,sizeof(Guard2));}
static BYTE* allocateNear(BYTE* call){
 uintptr_t center=(uintptr_t)call,low=center>0x70000000?center-0x70000000:0x10000,high=center+0x70000000;
 for(uintptr_t cursor=(low+65535)&~uintptr_t(65535);cursor<high;){MEMORY_BASIC_INFORMATION mi={};if(!VirtualQuery((void*)cursor,&mi,sizeof(mi)))break;
  uintptr_t end=(uintptr_t)mi.BaseAddress+mi.RegionSize;if(end<=cursor)break;
  if(mi.State==MEM_FREE){uintptr_t candidate=(cursor+65535)&~uintptr_t(65535);if(candidate+4096<=end&&candidate+4096<high){void* p=VirtualAlloc((void*)candidate,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(p)return (BYTE*)p;}}
  cursor=end;
 }return nullptr;
}
static HRESULT patchHotkey(bool restore){
 BYTE* site=twinuiBase+0xd350d;const BYTE* original=GuardHotkey+(0xd350d-0xd34ec);
 const BYTE* expected=restore?hotkeyCall:original;const BYTE* desired=restore?original:hotkeyCall;
 if(memcmp(site,expected,5))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 DWORD prot=0;if(!VirtualProtect(site,5,PAGE_EXECUTE_READWRITE,&prot))return HRESULT_FROM_WIN32(GetLastError());
 memcpy(site,desired,5);BOOL flushed=FlushInstructionCache(GetCurrentProcess(),site,5);DWORD error=flushed?0:GetLastError(),ignored;
 BOOL protectedAgain=VirtualProtect(site,5,prot,&ignored);if(!protectedAgain&&!error)error=GetLastError();
 return error?HRESULT_FROM_WIN32(error):S_OK;
}
static HRESULT install(bool fixture){
 if(WinXCompatStats.installed)return S_FALSE;
 if(WinXCompatStats.installError)return WinXCompatStats.installError;
 HMODULE main=GetModuleHandleW(nullptr);
 if(!fixture&&(!mappedAt(main,explorerPath)||!fileHash(explorerPath,explorerHash)))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 if(!fileHash(pcsPath,pcsHash)||!fileHash(udkPath,udkHash)||!fileHash(metadataPath,metadataHash)||!fileHash(twinuiPath,twinuiHash))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 HMODULE pcs=GetModuleHandleW(L"twinui.pcshell.dll");if(!pcs)pcs=LoadLibraryW(pcsPath);
 if(!pcs||!mappedAt(pcs,pcsPath))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 HMODULE udk=GetModuleHandleW(L"WindowsUdk.ShellCommon.dll");if(!udk)udk=LoadLibraryW(udkPath);
 if(!udk||!mappedAt(udk,udkPath))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 BYTE* b=(BYTE*)pcs;void**vt=(void**)(b+0x6ea9f8);if(!codeGuards(b))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 for(int i=0;i<5;i++)if(vt[i]!=b+methodRvas[i])return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 HMODULE twinui=GetModuleHandleW(L"twinui.dll");if(!twinui)twinui=LoadLibraryW(twinuiPath);
 if(!twinui||!mappedAt(twinui,twinuiPath))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 twinuiBase=(BYTE*)twinui;
 if(memcmp(twinuiBase+0xd34ec,GuardHotkey,sizeof(GuardHotkey))||memcmp(twinuiBase+0x3cf380,GuardHotkeyRegistration,sizeof(GuardHotkeyRegistration)))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 if(!hotkeyBridge){hotkeyBridge=allocateNear(twinuiBase+0xd350d);if(!hotkeyBridge)return E_OUTOFMEMORY;
  BYTE thunk[14]={0xff,0x25,0,0,0,0};void* target=(void*)&hotkey;memcpy(thunk+6,&target,8);memcpy(hotkeyBridge,thunk,14);DWORD old;
  if(!VirtualProtect(hotkeyBridge,4096,PAGE_EXECUTE_READ,&old)||!FlushInstructionCache(GetCurrentProcess(),hotkeyBridge,14)){VirtualFree(hotkeyBridge,0,MEM_RELEASE);hotkeyBridge=nullptr;return HRESULT_FROM_WIN32(GetLastError());}
 }
 INT64 displacement=hotkeyBridge-(twinuiBase+0xd350d+5);if(displacement<INT32_MIN||displacement>INT32_MAX)return E_BOUNDS;
 hotkeyCall[0]=0xe8;INT32 delta=(INT32)displacement;memcpy(hotkeyCall+1,&delta,4);
 // Pin the adapter before publishing any pointer into it. No loader lock work.
 if(!fixture){HMODULE pinned=nullptr;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(LPCWSTR)&show,&pinned))return HRESULT_FROM_WIN32(GetLastError());}
 DWORD oldProtect=0;if(!VirtualProtect(&vt[3],sizeof(void*),PAGE_READWRITE,&oldProtect))return HRESULT_FROM_WIN32(GetLastError());
 void* expected=b+methodRvas[3];void* prior=InterlockedCompareExchangePointer(&vt[3],(void*)&show,expected);
 DWORD ignored=0;bool restored=VirtualProtect(&vt[3],sizeof(void*),oldProtect,&ignored)!=FALSE;
 if(prior!=expected)return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 pcsBase=b;WinXCompatStats.slotAddress=(UINT64)&vt[3];WinXCompatStats.original=(UINT64)expected;WinXCompatStats.replacement=(UINT64)&show;
 WinXCompatStats.installed=1;
 if(!restored){WinXCompatStats.installError=HRESULT_FROM_WIN32(GetLastError());return WinXCompatStats.installError;}
 HRESULT h=patchHotkey(false);WinXCompatStats.hotkeyInstalled=!memcmp(twinuiBase+0xd350d,hotkeyCall,5);
 if(FAILED(h)){WinXCompatStats.installError=h;return h;}
 WinXHotkeyPointers[0]=(UINT64)twinuiBase;WinXHotkeyPointers[1]=(UINT64)(twinuiBase+0xd350d);WinXHotkeyPointers[2]=(UINT64)hotkeyBridge;
 return S_OK;
}
extern "C" __declspec(dllexport) DWORD WINAPI WinXCompatInitialize(void*){
 HRESULT hr=install(false);if(FAILED(hr))WinXCompatStats.installError=hr;return hr;
}
extern "C" __declspec(dllexport) DWORD WINAPI WinXCompatRestore(void*){
 if(InterlockedCompareExchange(&showBusy,1,0))return HRESULT_FROM_WIN32(ERROR_BUSY);
 HRESULT hr=S_FALSE;
 if(WinXCompatStats.hotkeyInstalled){hr=patchHotkey(true);if(FAILED(hr)){InterlockedExchange(&showBusy,0);return hr;}WinXCompatStats.hotkeyInstalled=0;}
 if(WinXCompatStats.installed){void**slot=(void**)WinXCompatStats.slotAddress;DWORD prot=0;
  if(*slot!=(void*)&show)hr=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
  else if(!VirtualProtect(slot,8,PAGE_READWRITE,&prot))hr=HRESULT_FROM_WIN32(GetLastError());
  else {void* p=InterlockedCompareExchangePointer(slot,(void*)WinXCompatStats.original,(void*)&show);DWORD ignore;
   BOOL okay=VirtualProtect(slot,8,prot,&ignore);hr=p==(void*)&show?(okay?S_OK:HRESULT_FROM_WIN32(GetLastError())):HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
   if(SUCCEEDED(hr)){WinXCompatStats.installed=0;WinXCompatStats.installError=0;}
  }
 }
 InterlockedExchange(&showBusy,0);return hr;
}

static HRESULT waitReady(AsyncInfo* info,DWORD timeout){
 ULONGLONG start=GetTickCount64(),end=start+timeout;WinXQueryTrace[0]=timeout;
 struct Elapsed {ULONGLONG begin;~Elapsed(){WinXQueryTrace[1]=(DWORD)(GetTickCount64()-begin);}} elapsed{start};
 for(;;){INT status=-1;HRESULT hr=info->Status(&status);WinXQueryTrace[2]=status;WinXQueryTrace[3]=hr;if(FAILED(hr))return hr;
  if(status==1)return S_OK;
  if(status==2)return HRESULT_FROM_WIN32(ERROR_CANCELLED);
  if(status==3){HRESULT error=E_FAIL;hr=info->Error(&error);WinXQueryTrace[4]=error;return FAILED(hr)?hr:FAILED(error)?error:E_UNEXPECTED;}
  if(status!=0)return E_UNEXPECTED;
  if(GetTickCount64()>=end){WinXQueryTrace[6]=info->Cancel();return HRESULT_FROM_WIN32(ERROR_TIMEOUT);}
  // Normal STA modal dispatch; never synthesize input. Reentrant Show is gated.
  DWORD wait=MsgWaitForMultipleObjectsEx(0,nullptr,20,QS_ALLINPUT,MWMO_INPUTAVAILABLE|MWMO_ALERTABLE);
  if(wait==WAIT_FAILED)return HRESULT_FROM_WIN32(GetLastError());
  MSG msg;while(PeekMessageW(&msg,nullptr,0,0,PM_REMOVE)){
   if(msg.message==WM_QUIT){PostQuitMessage((int)msg.wParam);info->Cancel();return E_ABORT;}
   TranslateMessage(&msg);DispatchMessageW(&msg);
   if(GetTickCount64()>=end)break;
  }
 }
}
static HRESULT getItems(Tip* tip,RECT anchor,MenuVector** output,DWORD timeout=5000){
 ZeroMemory(WinXQueryTrace,sizeof(WinXQueryTrace));
 *output=nullptr;Ref<IUnknown> raw;HRESULT hr=tip->Items(anchor,raw.out());if(FAILED(hr)||!raw)return FAILED(hr)?hr:E_UNEXPECTED;
 Ref<AsyncResult> operation;hr=raw->QueryInterface(IID_Operation,(void**)operation.out());if(FAILED(hr)||!operation)return FAILED(hr)?hr:E_UNEXPECTED;
 Ref<AsyncInfo> info;hr=operation->QueryInterface(IID_AsyncInfo,(void**)info.out());if(FAILED(hr)||!info)return FAILED(hr)?hr:E_UNEXPECTED;
 hr=waitReady(info.p,timeout);WinXQueryTrace[5]=hr;if(FAILED(hr))return hr;
 Ref<MenuVector> rawVector;hr=operation->Results(rawVector.out());if(FAILED(hr)||!rawVector)return FAILED(hr)?hr:E_UNEXPECTED;
 return rawVector->QueryInterface(IID_Vector,(void**)output);
}
struct MenuTree {
 HMENU root=nullptr;MenuItem* commands[128]={};UINT count=0,total=0;
 ~MenuTree(){if(root)DestroyMenu(root);for(UINT i=0;i<count;i++)if(commands[i])commands[i]->Release();}
 HRESULT add(MenuVector* vector,HMENU menu,UINT depth=0){
  if(depth>4)return HRESULT_FROM_WIN32(ERROR_STACK_OVERFLOW);
  UINT n=0;HRESULT hr=vector->Size(&n);if(FAILED(hr))return hr;if(n>128)return E_BOUNDS;
  for(UINT i=0;i<n;i++){
   if(++total>128)return E_BOUNDS;
   Ref<MenuItem> raw,item;hr=vector->At(i,raw.out());if(FAILED(hr)||!raw)return FAILED(hr)?hr:E_UNEXPECTED;
   hr=raw->QueryInterface(IID_MenuItem,(void**)item.out());if(FAILED(hr)||!item)return FAILED(hr)?hr:E_UNEXPECTED;
   UINT states=0;INT kind=-1;hr=item->States(&states);if(FAILED(hr))return hr;
   if(states&2)continue;hr=item->Kind(&kind);if(FAILED(hr))return hr;
   MENUITEMINFOW m={sizeof(m)};m.fMask=MIIM_FTYPE|MIIM_STATE;m.fState=(states&1)?MFS_DISABLED:MFS_ENABLED;
   if(states&8)m.fState|=MFS_CHECKED;if(states&16)m.fType|=MFT_RADIOCHECK;
   Str name;
   if(kind==2)m.fType=MFT_SEPARATOR;
   else {
    if(kind!=0&&kind!=1)return E_UNEXPECTED;
    hr=item->DisplayName(&name.h);if(FAILED(hr))return hr;
    UINT len=0;const wchar_t* text=WindowsGetStringRawBuffer(name.h,&len);if(!len||len>4096||wcslen(text)!=len)return E_UNEXPECTED;
    m.fMask|=MIIM_STRING;m.dwTypeData=(LPWSTR)text;m.cch=len;
    if(kind==1){Ref<MenuVector> children;hr=item->SubItems(children.out());if(FAILED(hr)||!children)return FAILED(hr)?hr:E_UNEXPECTED;
     HMENU sub=CreatePopupMenu();if(!sub)return HRESULT_FROM_WIN32(GetLastError());hr=add(children.p,sub,depth+1);
     if(FAILED(hr)){DestroyMenu(sub);return hr;}m.fMask|=MIIM_SUBMENU;m.hSubMenu=sub;
    }else{if(count>=128)return E_BOUNDS;m.fMask|=MIIM_ID;m.wID=count+1;commands[count++]=item.p;item.p=nullptr;}
   }
   if(!InsertMenuItemW(menu,(UINT)-1,TRUE,&m)){hr=HRESULT_FROM_WIN32(GetLastError());if(m.hSubMenu)DestroyMenu(m.hSubMenu);return hr;}
  }return S_OK;
 }
 HRESULT build(MenuVector* vector){root=CreatePopupMenu();return root?add(vector,root):HRESULT_FROM_WIN32(GetLastError());}
 HRESULT invoke(UINT id){if(!id||id>count)return E_INVALIDARG;Ref<AsyncAction> action;HRESULT hr=commands[id-1]->Invoke(action.out());if(FAILED(hr)||!action)return FAILED(hr)?hr:E_UNEXPECTED;
  Ref<AsyncInfo> info;hr=action->QueryInterface(IID_AsyncInfo,(void**)info.out());if(FAILED(hr)||!info)return FAILED(hr)?hr:E_UNEXPECTED;
  // Invocation is already genuine and may launch/log off. Do not cancel it.
  INT status=-1;hr=info->Status(&status);if(FAILED(hr))return hr;
  if(status==3){HRESULT error=E_FAIL;hr=info->Error(&error);return FAILED(hr)?hr:FAILED(error)?error:E_UNEXPECTED;}
  return S_OK;
 }
};
static HRESULT STDMETHODCALLTYPE show(Tip* self,POINT* requested){
 if(!WinXCompatStats.installed)return E_ABORT;
 WinXCompatStats.calls++;
 if(InterlockedCompareExchange(&showBusy,1,0)){WinXCompatStats.busy++;if(WinXCompatStats.callerThread==GetCurrentThreadId())EndMenu();return S_FALSE;}
 struct Busy {~Busy(){InterlockedExchange(&showBusy,0);}} busy;
 memset(WinXOwnerTrace,0,sizeof(WinXOwnerTrace));memset(WinXQueryTrace,0,sizeof(WinXQueryTrace));memset(WinXFocusTrace,0,sizeof(WinXFocusTrace));
 WinXCompatStats.callerThread=GetCurrentThreadId();
 APTTYPE apartment=APTTYPE_CURRENT;APTTYPEQUALIFIER qualifier=APTTYPEQUALIFIER_NONE;HRESULT hr=CoGetApartmentType(&apartment,&qualifier);WinXCompatStats.apartment=apartment;
 if(FAILED(hr)||(apartment!=APTTYPE_STA&&apartment!=APTTYPE_MAINSTA))return last(FAILED(hr)?hr:RPC_E_WRONG_THREAD);
 if(!self||*(void***)self!=(void**)(pcsBase+0x6ea9f8))return last(E_NOINTERFACE);
 self->AddRef();Ref<Tip> held;held.p=self;
 HWND tray=FindWindowW(L"Shell_TrayWnd",nullptr);DWORD ownerPid=0;GetWindowThreadProcessId(tray,&ownerPid);if(!tray||ownerPid!=GetCurrentProcessId())return last(E_ACCESSDENIED);
 HWND start=FindWindowExW(tray,nullptr,L"Start",nullptr);RECT rect={};if(!GetWindowRect(start?start:tray,&rect))return last(HRESULT_FROM_WIN32(GetLastError()));
 MONITORINFO mi={sizeof(mi)};if(!GetMonitorInfoW(MonitorFromWindow(tray,MONITOR_DEFAULTTONEAREST),&mi))return last(HRESULT_FROM_WIN32(GetLastError()));
 RECT bar={};GetWindowRect(tray,&bar);POINT point={rect.left,rect.top};UINT flags=TPM_RETURNCMD|TPM_RIGHTBUTTON;
 bool bottom=bar.top>=mi.rcWork.bottom-2;if(bottom)flags|=TPM_BOTTOMALIGN;else {point.y=rect.bottom;flags|=TPM_TOPALIGN;}
 if(requested&&!(requested->x==-1&&requested->y==-1))point=*requested;
 RECT anchor={point.x,point.y,point.x+1,point.y+1};Ref<MenuVector> items;
 // Actual b004 telemetry showed its first native enumeration still Started at5s.
 // Allow a bounded15s cold query, retain5s after a successful query, report failure.
 hr=getItems(self,anchor,items.out(),WinXCompatStats.completed?5000:15000);
 if(FAILED(hr)){if(hr==HRESULT_FROM_WIN32(ERROR_TIMEOUT))WinXCompatStats.timeouts++;return last(hr);}WinXCompatStats.completed++;
 MenuTree tree;hr=tree.build(items.p);if(FAILED(hr))return last(hr);WinXCompatStats.menusBuilt++;WinXCompatStats.lastItemCount=tree.total;
 MenuOwner owner;DWORD createError=owner.window?0:GetLastError();WinXOwnerTrace[0]=(UINT64)owner.window;WinXOwnerTrace[1]=GetCurrentThreadId();WinXOwnerTrace[2]=owner.window?GetWindowThreadProcessId(owner.window,nullptr):0;WinXOwnerTrace[3]=createError;
 if(!owner.window)return last(HRESULT_FROM_WIN32(createError?createError:ERROR_INVALID_WINDOW_HANDLE));
 if(WinXOwnerTrace[2]!=WinXOwnerTrace[1])return last(E_UNEXPECTED);
 WinXFocusTrace[0]=(UINT64)GetForegroundWindow();WinXFocusTrace[1]=SetForegroundWindow(owner.window);WinXFocusTrace[2]=(UINT64)GetForegroundWindow();SetLastError(0);ULONGLONG popupStart=GetTickCount64();
 UINT selected=TrackPopupMenuEx(tree.root,flags,point.x,point.y,owner.window,nullptr);DWORD error=GetLastError();
 WinXOwnerTrace[4]=error;WinXOwnerTrace[5]=GetTickCount64()-popupStart;
 WinXCompatStats.selected=selected;if(!selected)return last(error?HRESULT_FROM_WIN32(error):S_OK);
 hr=tree.invoke(selected);if(SUCCEEDED(hr))WinXCompatStats.invoked++;return last(hr);
}
static bool WINAPI hotkey(){
 // Replaces exactly the native OnMessage ID0x0f callsite, never the shared predicate.
 APTTYPE apt=APTTYPE_CURRENT;APTTYPEQUALIFIER qualifier=APTTYPEQUALIFIER_NONE;HRESULT aptHR=CoGetApartmentType(&apt,&qualifier);
 WinXHotkeyTrace[0]=GetCurrentThreadId();WinXHotkeyTrace[1]=apt;WinXHotkeyTrace[2]=qualifier;WinXHotkeyTrace[3]=aptHR;
 bool desktop=((bool(WINAPI*)())(twinuiBase+0x21980c))();WinXCompatStats.hotkeyCalls++;WinXHotkeyTrace[4]=desktop;WinXHotkeyTrace[5]=1;
 if(!desktop)return false;
 HWND tray=FindWindowW(L"Shell_TrayWnd",nullptr);DWORD pid=0;GetWindowThreadProcessId(tray,&pid);
 if(!tray||pid!=GetCurrentProcessId()){WinXHotkeyTrace[6]=E_ACCESSDENIED;last(E_ACCESSDENIED);return desktop;}
 HWND start=FindWindowExW(tray,nullptr,L"Start",nullptr);
 Ref<IServiceProvider> shell;Ref<MonitorManager> monitors;Ref<Tip> tip;
 HRESULT hr=CoCreateInstance(CLSID_Shell,nullptr,CLSCTX_LOCAL_SERVER,IID_IServiceProvider,(void**)shell.out());
 WinXHotkeyTrace[5]=2;
 if(SUCCEEDED(hr)&&shell){WinXHotkeyTrace[5]=3;hr=shell->QueryService(SID_MonitorManager,IID_MonitorManager,(void**)monitors.out());}
 if(SUCCEEDED(hr)&&monitors){WinXHotkeyTrace[5]=4;hr=monitors->QueryServiceFromWindow(start?start:tray,IID_Tip,IID_Tip,(void**)tip.out());}
 if(SUCCEEDED(hr)&&tip){WinXHotkeyTrace[5]=5;hr=show(tip.p,nullptr);}else if(SUCCEEDED(hr))hr=E_UNEXPECTED;
 WinXHotkeyTrace[6]=hr;
 last(hr);return desktop;
}
