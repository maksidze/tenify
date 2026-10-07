#include "WinXCompat.Immersive.cpp"
#include <shellapi.h>
#include <stdio.h>
static FILE* output;
#define CHECK(test) do{bool value=!!(test);fwprintf(output,L"%ls %hs line%d\n",value?L"PASS":L"FAIL",#test,__LINE__);fflush(output);if(!value)return 20;}while(0)
static DWORD WINAPI watchdog(void*){Sleep(18000);ExitProcess(0xdeca);return 0;}
struct TestInfo:AsyncInfo {
 LONG refs=1;int mode=0;bool canceled=false;UINT* destroyed;
 TestInfo(int m,UINT*d):mode(m),destroyed(d){}
 HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void**out)override{*out=nullptr;if(id!=IID_IUnknown&&id!=IID_Inspectable&&id!=IID_AsyncInfo)return E_NOINTERFACE;*out=this;AddRef();return S_OK;}
 ULONG STDMETHODCALLTYPE AddRef()override{return InterlockedIncrement(&refs);}ULONG STDMETHODCALLTYPE Release()override{auto n=InterlockedDecrement(&refs);if(!n){++*destroyed;delete this;}return n;}
 HRESULT STDMETHODCALLTYPE GetIids(ULONG*n,IID**v)override{*n=0;*v=nullptr;return E_NOTIMPL;}
 HRESULT STDMETHODCALLTYPE GetRuntimeClassName(HSTRING*h)override{*h=nullptr;return E_NOTIMPL;}
 HRESULT STDMETHODCALLTYPE GetTrustLevel(TrustLevel*t)override{*t=BaseTrust;return S_OK;}
 HRESULT STDMETHODCALLTYPE Id(UINT*n)override{*n=1;return S_OK;}
 HRESULT STDMETHODCALLTYPE Status(INT*n)override{*n=mode;return S_OK;}
 HRESULT STDMETHODCALLTYPE Error(HRESULT*e)override{*e=E_ACCESSDENIED;return S_OK;}
 HRESULT STDMETHODCALLTYPE Cancel()override{canceled=true;return S_OK;}
 HRESULT STDMETHODCALLTYPE Close()override{return S_OK;}
};
static HRESULT verifyMenu(MenuVector* vector,HMENU menu,UINT depth=0){
 UINT n=0;HRESULT hr=vector->Size(&n);if(FAILED(hr))return hr;int pos=0;
 for(UINT i=0;i<n;i++){Ref<MenuItem> item;hr=vector->At(i,item.out());if(FAILED(hr)||!item)return E_FAIL;
  UINT states=0;INT kind=-1;if(FAILED(item->States(&states))||FAILED(item->Kind(&kind)))return E_FAIL;if(states&2)continue;
  wchar_t text[4097];MENUITEMINFOW info={sizeof(info)};info.fMask=MIIM_STRING|MIIM_STATE|MIIM_FTYPE|MIIM_SUBMENU|MIIM_ID;info.dwTypeData=text;info.cch=4097;
  if(!GetMenuItemInfoW(menu,pos++,TRUE,&info)){fwprintf(output,L"GetMenuItemInfo failed %lu\n",GetLastError());return E_FAIL;}
  fwprintf(output,L"VERIFY depth%u item%u kind%d states%x fState%x fType%x ID%u sub%p label[%ls]\n",depth,i,kind,states,info.fState,info.fType,info.wID,info.hSubMenu,text);fflush(output);
  if(kind==2){if(!(info.fType&MFT_SEPARATOR))return E_FAIL;continue;}
  if((bool)(info.fState&MFS_DISABLED)!=(bool)(states&1)||(bool)(info.fState&MFS_CHECKED)!=(bool)(states&8))return E_FAIL;
  Str name;if(FAILED(item->DisplayName(&name.h))||wcscmp(text,name.text())){fwprintf(output,L"LABEL depth%u item%u actual[%ls] expected[%ls] len%u\n",depth,i,text,name.text(),info.cch);return E_FAIL;}
  if(kind==1){Ref<MenuVector> sub;if(FAILED(item->SubItems(sub.out()))||!sub||!info.hSubMenu||FAILED(verifyMenu(sub.p,info.hSubMenu,depth+1)))return E_FAIL;}
  else if(!info.wID)return E_FAIL;
 }
 if(GetMenuItemCount(menu)!=pos){fwprintf(output,L"COUNT depth%u actual%d expected%d\n",depth,GetMenuItemCount(menu),pos);return E_FAIL;}return S_OK;
}
int run(){
 CHECK(RoInitialize(RO_INIT_SINGLETHREADED)==S_OK);
 UINT destroyed=0;
 {Ref<TestInfo> wait;wait.p=new TestInfo(0,&destroyed);ULONGLONG begin=GetTickCount64();CHECK(waitReady(wait.p,40)==HRESULT_FROM_WIN32(ERROR_TIMEOUT));CHECK(wait->canceled);CHECK(GetTickCount64()-begin<1000);}
 {Ref<TestInfo> fail;fail.p=new TestInfo(3,&destroyed);CHECK(waitReady(fail.p,40)==E_ACCESSDENIED);CHECK(!fail->canceled);}
 {Ref<TestInfo> done;done.p=new TestInfo(1,&destroyed);CHECK(waitReady(done.p,40)==S_OK);CHECK(!done->canceled);}
 CHECK(destroyed==3);
 CHECK(install(false)==HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH)); // Own fixture is NOT Explorer.
 HMODULE pcs=LoadLibraryW(pcsPath);CHECK(pcs!=nullptr);BYTE* base=(BYTE*)pcs;void** vt=(void**)(base+0x6ea9f8);void* old[5];memcpy(old,vt,sizeof(old));
 CHECK(install(true)==S_OK);CHECK(vt[3]==(void*)&show);CHECK(!memcmp(base+0x241ef0,Guard0,3));
 CHECK(WinXCompatStats.hotkeyInstalled==1);CHECK(!memcmp(twinuiBase+0xd350d,hotkeyCall,5));
 bool originalContext=((bool(WINAPI*)())(twinuiBase+0x21980c))();
 CHECK(((bool(WINAPI*)())hotkeyBridge)()==originalContext);CHECK(WinXCompatStats.hotkeyCalls==1);CHECK(WinXCompatStats.calls==0);
 CHECK(vt[0]==old[0]&&vt[1]==old[1]&&vt[2]==old[2]&&vt[4]==old[4]);
 CHECK(WinXCompatRestore(nullptr)==S_OK);CHECK(!memcmp(vt,old,sizeof(old)));CHECK(WinXCompatStats.hotkeyInstalled==0);CHECK(!memcmp(twinuiBase+0xd34ec,GuardHotkey,sizeof(GuardHotkey)));CHECK(WinXCompatRestore(nullptr)==S_FALSE);
 DWORD prot=0,ignored;CHECK(VirtualProtect(&vt[4],8,PAGE_READWRITE,&prot));vt[4]=old[3];CHECK(VirtualProtect(&vt[4],8,prot,&ignored));
 CHECK(install(true)==HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH));CHECK(vt[3]==old[3]);
 CHECK(VirtualProtect(&vt[4],8,PAGE_READWRITE,&prot));vt[4]=old[4];CHECK(VirtualProtect(&vt[4],8,prot,&ignored));
 auto getClass=(HRESULT(WINAPI*)(REFCLSID,REFIID,void**))GetProcAddress(pcs,"DllGetClassObject");CHECK(getClass!=nullptr);
 {Ref<IClassFactory> factory;Ref<Tip> tip;Ref<IObjectWithSite> site;Ref<IServiceProvider> shell;
  CHECK(getClass(CLSID_Tip,IID_IClassFactory,(void**)factory.out())==S_OK);
  CHECK(factory->CreateInstance(nullptr,IID_Tip,(void**)tip.out())==S_OK);
  CHECK(tip->QueryInterface(IID_IObjectWithSite,(void**)site.out())==S_OK);
  CHECK(CoCreateInstance(CLSID_Shell,nullptr,CLSCTX_LOCAL_SERVER,IID_IServiceProvider,(void**)shell.out())==S_OK);
  CHECK(site->SetSite(shell.p)==S_OK);
  {Ref<MenuVector> items;RECT anchor={0,0,1,1};CHECK(getItems(tip.p,anchor,items.out())==S_OK);UINT n=0;CHECK(items->Size(&n)==S_OK&&n>0);
   MenuTree tree;CHECK(tree.build(items.p)==S_OK);CHECK(tree.root!=nullptr);CHECK(verifyMenu(items.p,tree.root)==S_OK);CHECK(tree.count>0&&tree.total>=n);
   {MenuOwner owner;CHECK(owner.window);POINT point={0,0};{ImmersiveMenu immersive(tree.root,owner.window,&point);CHECK(immersive.hr==S_OK&&immersive.array.count>0);CHECK(verifyMenu(items.p,tree.root)==S_OK);}CHECK(verifyMenu(items.p,tree.root)==S_OK);CHECK(WinXRendererTrace[9]==0);}
   CHECK(tree.invoke(0)==E_INVALIDARG);CHECK(tree.invoke(tree.count+1)==E_INVALIDARG);
   fwprintf(output,L"REAL menu top=%u treeTotal=%u commands=%u; no Show/TrackPopupMenu/Invoke called\n",n,tree.total,tree.count);fflush(output);
  }
  CHECK(site->SetSite(nullptr)==S_OK);
 }
 RoUninitialize();fwprintf(output,L"COMPLETE: actual native menu comparison, guarded own-process slot install/restore, timeout/error/refcount negatives PASS\n");return 0;
}
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){int argc;auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(argc!=2)return 2;_wfopen_s(&output,argv[1],L"w, ccs=UTF-8");if(!output)return 3;HANDLE t=CreateThread(nullptr,0,watchdog,nullptr,0,nullptr);if(!t)return 4;CloseHandle(t);int status=run();fclose(output);LocalFree(argv);return status;}
