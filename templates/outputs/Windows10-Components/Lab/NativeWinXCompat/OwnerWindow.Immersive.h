#pragma once
// The popup owner must belong to the calling GUI thread. It is never shown.
static LRESULT CALLBACK menuOwnerProc(HWND w,UINT m,WPARAM a,LPARAM b){if(m==WM_MENUCHAR){LRESULT result;if(rendererMenuChar(w,a,b,&result))return result;}
 if(rendererDispatch(w,m,a,b))return TRUE;return DefWindowProcW(w,m,a,b);}
static INIT_ONCE ownerClassOnce=INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK registerOwnerClass(PINIT_ONCE,void*,void**){
 WNDCLASSW c={};c.lpfnWndProc=menuOwnerProc;c.hInstance=GetModuleHandleW(nullptr);c.lpszClassName=L"Explorer10.WinXCompat.ImmersiveOwner.v3";
 if(RegisterClassW(&c))return TRUE;
 if(GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)return FALSE;
 WNDCLASSW current={};return GetClassInfoW(c.hInstance,c.lpszClassName,&current)&&current.lpfnWndProc==menuOwnerProc;
}
static HWND createMenuOwner(){
 if(!InitOnceExecuteOnce(&ownerClassOnce,registerOwnerClass,nullptr,nullptr))return nullptr;
 return CreateWindowExW(WS_EX_TOOLWINDOW,L"Explorer10.WinXCompat.ImmersiveOwner.v3",L"",WS_POPUP,0,0,1,1,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
}
struct MenuOwner {
 HWND window=nullptr;MenuOwner():window(createMenuOwner()){};
 ~MenuOwner(){if(window)DestroyWindow(window);}
 MenuOwner(const MenuOwner&)=delete;MenuOwner& operator=(const MenuOwner&)=delete;
};
