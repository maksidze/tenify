#pragma once
#include "RendererGuards.h"
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
static HRESULT rendererInitialize(BYTE* base){
 if(memcmp(base+0x6611f4,RendererGuardApply,sizeof(RendererGuardApply))||memcmp(base+0x661b18,RendererGuardRemove,sizeof(RendererGuardRemove))||memcmp(base+0x65f754,RendererGuardWndProc,sizeof(RendererGuardWndProc))||memcmp(base+0x4c1184,RendererGuardDestroyArray,sizeof(RendererGuardDestroyArray))||memcmp(base+0x4c1134,RendererGuardDestroyArrayBase,sizeof(RendererGuardDestroyArrayBase)))return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
 rendererApply=(RendererApplyFn)(base+0x6611f4);rendererRemove=(RendererRemoveFn)(base+0x661b18);rendererDestroy=(RendererDestroyFn)(base+0x4c1184);rendererProc=(RendererProcFn)(base+0x65f754);WinXRendererTrace[0]=1;return S_OK;
}
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
struct ImmersiveMenu {
 static constexpr UINT64 Canary=0xa52d87453ce019b6;
 UINT64 before=Canary;RendererArray array;UINT64 after=Canary;
 HMENU menu;HWND owner;HRESULT hr=E_UNEXPECTED;bool attempted=false;
 ImmersiveMenu(HMENU m,HWND w,POINT* anchor):menu(m),owner(w){
  if(!rendererApply||GetWindowLongPtrW(owner,GWLP_USERDATA))return;
  SetWindowLongPtrW(owner,GWLP_USERDATA,(LONG_PTR)menu);attempted=true;WinXRendererTrace[1]++;WinXRendererTrace[7]=0xc;
  hr=rendererApply(menu,owner,anchor,0xc,&array);WinXRendererTrace[6]=hr;WinXRendererTrace[8]=(DWORD)array.count;
  if(before!=Canary||after!=Canary){WinXRendererTrace[9]++;hr=E_UNEXPECTED;}else if(SUCCEEDED(hr))WinXRendererTrace[2]++;
 }
 ~ImmersiveMenu(){if(attempted){rendererRemove(menu,owner);WinXRendererTrace[3]++;SetWindowLongPtrW(owner,GWLP_USERDATA,0);rendererDestroy(&array);if(before!=Canary||after!=Canary)WinXRendererTrace[9]++;}}
 ImmersiveMenu(const ImmersiveMenu&)=delete;ImmersiveMenu& operator=(const ImmersiveMenu&)=delete;
};
