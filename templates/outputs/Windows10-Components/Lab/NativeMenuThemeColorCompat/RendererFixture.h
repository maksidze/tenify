#pragma once
static const BYTE rg1_0[]={@GENERATED_GUARD_35@};
static const BYTE rg1_1[]={@GENERATED_GUARD_36@};
static const BYTE rg1_2[]={@GENERATED_GUARD_37@};
static const BYTE rg1_3[]={@GENERATED_GUARD_38@};
static const BYTE rg2_0[]={@GENERATED_GUARD_39@};
static const BYTE rg2_1[]={@GENERATED_GUARD_40@};
static const BYTE rg2_2[]={@GENERATED_GUARD_41@};
static const BYTE rg2_3[]={@GENERATED_GUARD_42@};
static const BYTE shellFixtureHash[]={0xbd,0x11,0xe6,0x17,0xc0,0x92,0xa8,0x2a,0xde,0xca,0xd3,0x18,0x31,0x38,0x9e,0x52,0x22,0x6a,0xb,0x27,0x92,0xe7,0xe3,0xf0,0x1e,0x5c,0xee,0x51,0x6c,0x7c,0xa4,0xd0};
// All four members and the matching native destructor are from the same PCS image.
struct RendererArray {void* data=nullptr;size_t count=0;void* temporary=nullptr;size_t capacity=0;};
static_assert(sizeof(RendererArray)==32,"native CSimplePointerArrayNewMem layout");
typedef HRESULT(WINAPI* RendererApplyFn)(HMENU,HWND,POINT*,UINT,RendererArray*);
typedef void(WINAPI* RendererRemoveFn)(HMENU,HWND);
typedef void(WINAPI* RendererDestroyFn)(RendererArray*);
typedef bool(WINAPI* RendererProcFn)(HWND,UINT,WPARAM,LPARAM,bool*,UINT*);
static RendererApplyFn rendererApply;
static RendererRemoveFn rendererRemove;
static RendererDestroyFn rendererDestroy;
static RendererProcFn rendererProc;
extern "C" __declspec(dllexport) DWORD WinXRendererTrace[10]={}; // version,apply,success,remove,measure,draw,lastHR,flags,arrayCount,canaryFailures
static HRESULT rendererSelect(BYTE*base,int kind){
 if(kind!=1&&kind!=2)return E_INVALIDARG;
 if(kind==1){
  if(memcmp(base+0x6611f4,rg1_0,32))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
  if(memcmp(base+0x661b18,rg1_1,32))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
  if(memcmp(base+0x65f754,rg1_2,32))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
  if(memcmp(base+0x4c1184,rg1_3,32))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
  rendererApply=(RendererApplyFn)(base+0x6611f4);
  rendererRemove=(RendererRemoveFn)(base+0x661b18);
  rendererProc=(RendererProcFn)(base+0x65f754);
  rendererDestroy=(RendererDestroyFn)(base+0x4c1184);
 }
 if(kind==2){
  if(memcmp(base+0x127fd8,rg2_0,32))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
  if(memcmp(base+0x12858c,rg2_1,32))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
  if(memcmp(base+0x15db9c,rg2_2,32))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
  if(memcmp(base+0x1f5498,rg2_3,32))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
  rendererApply=(RendererApplyFn)(base+0x127fd8);
  rendererRemove=(RendererRemoveFn)(base+0x12858c);
  rendererProc=(RendererProcFn)(base+0x15db9c);
  rendererDestroy=(RendererDestroyFn)(base+0x1f5498);
 }
 WinXRendererTrace[0]=1;return S_OK;}
static bool rendererContainsMenu(HMENU root,HMENU target,UINT depth=0){
 if(!root||depth>4)return false;if(root==target)return true;int n=GetMenuItemCount(root);if(n<0||n>128)return false;
 for(int i=0;i<n;i++){HMENU sub=GetSubMenu(root,i);if(sub&&rendererContainsMenu(sub,target,depth+1))return true;}return false;
}
static bool rendererDispatch(HWND window,UINT message,WPARAM w,LPARAM l){
 if(!rendererProc)return false;
 HMENU root=(HMENU)GetWindowLongPtrW(window,GWLP_USERDATA);
 if(message==WM_INITMENUPOPUP){if(!rendererContainsMenu(root,(HMENU)w))return false;bool ignored=false;UINT flags=0;return rendererProc(window,message,w,l,&ignored,&flags);}
 if(!root||!l||(message!=WM_MEASUREITEM&&message!=WM_DRAWITEM))return false;
 // Menu messages only. Do not send unrelated owner-drawn controls to the renderer.
 if(w||*(UINT*)l!=ODT_MENU)return false;
 bool handled=false;UINT selection=0;bool result=rendererProc(window,message,w,l,&handled,&selection);
 if(result)InterlockedIncrement((LONG*)&WinXRendererTrace[message==WM_MEASUREITEM?4:5]);return result;
}
static bool rendererMenuChar(HWND window,WPARAM input,LPARAM parameter,LRESULT* result){
 HMENU root=(HMENU)GetWindowLongPtrW(window,GWLP_USERDATA),menu=(HMENU)parameter;
 if(!rendererContainsMenu(root,menu))return false;
 wchar_t key=(wchar_t)LOWORD(input);int n=GetMenuItemCount(menu),matched[128],count=0,highlighted=-1;
 for(int i=0;i<n&&i<128;i++){
  wchar_t label[4097];MENUITEMINFOW item={sizeof(item)};item.fMask=MIIM_STRING|MIIM_STATE|MIIM_FTYPE;item.dwTypeData=label;item.cch=4097;
  if(!GetMenuItemInfoW(menu,i,TRUE,&item))continue;if(item.fState&MFS_HILITE)highlighted=i;
  if((item.fType&MFT_SEPARATOR)||(item.fState&MFS_DISABLED)||!item.cch||item.cch>=4097)continue;
  const wchar_t* mnemonic=nullptr;for(UINT j=0;j<item.cch;j++){if(label[j]==L'&'){if(j+1<item.cch&&label[j+1]==L'&'){j++;continue;}if(j+1<item.cch)mnemonic=label+j+1;break;}}
  // Native MenuCharMatch also uses first character when no explicit mnemonic exists.
  if(!mnemonic)mnemonic=label;
  if(CompareStringOrdinal(mnemonic,1,&key,1,TRUE)==CSTR_EQUAL)matched[count++]=i;
 }
 if(!count){*result=MAKELRESULT(0,MNC_IGNORE);return true;}
 int selected=matched[0];if(count>1)for(int i=0;i<count;i++)if(matched[i]>highlighted){selected=matched[i];break;}
 *result=MAKELRESULT(selected,count==1?MNC_EXECUTE:MNC_SELECT);return true;
}
static UINT ownRendererFlags=0xc;
struct ImmersiveMenu {
 static constexpr UINT64 Canary=0xa52d87453ce019b6;
 UINT64 before=Canary;RendererArray array;UINT64 after=Canary;
 HMENU menu;HWND owner;HRESULT hr=E_UNEXPECTED;bool attempted=false;
 ImmersiveMenu(HMENU m,HWND w,POINT* anchor):menu(m),owner(w){
  if(!rendererApply||GetWindowLongPtrW(owner,GWLP_USERDATA))return;
  SetWindowLongPtrW(owner,GWLP_USERDATA,(LONG_PTR)menu);attempted=true;WinXRendererTrace[1]++;WinXRendererTrace[7]=ownRendererFlags;
  hr=rendererApply(menu,owner,anchor,ownRendererFlags,&array);WinXRendererTrace[6]=hr;WinXRendererTrace[8]=(DWORD)array.count;
  if(before!=Canary||after!=Canary){WinXRendererTrace[9]++;hr=E_UNEXPECTED;}else if(SUCCEEDED(hr))WinXRendererTrace[2]++;
 }
 ~ImmersiveMenu(){if(attempted){rendererRemove(menu,owner);WinXRendererTrace[3]++;SetWindowLongPtrW(owner,GWLP_USERDATA,0);rendererDestroy(&array);if(before!=Canary||after!=Canary)WinXRendererTrace[9]++;}}
 ImmersiveMenu(const ImmersiveMenu&)=delete;ImmersiveMenu& operator=(const ImmersiveMenu&)=delete;
};
