#pragma once
#include <windows.h>
#include <inspectable.h>
#include <roapi.h>
#include <winstring.h>
#include <objbase.h>
#include <servprov.h>
#include <ocidl.h>
static const GUID IID_Inspectable={0xaf86e2e0,0xb12d,0x4c6a,{0x9c,0x5a,0xd7,0xaa,0x65,0x10,0x1e,0x90}};
static const GUID IID_Tip={0xb8c1db5f,0xcbb3,0x48bc,{0xaf,0xd9,0xce,0x6b,0x88,0x0c,0x79,0xed}};
static const GUID CLSID_Tip={0x51d1268c,0xd0a5,0x47cc,{0xa5,0x14,0x54,0x7f,0x34,0x6f,0x45,0xe8}};
static const GUID CLSID_Shell={0xc2f03a33,0x21f5,0x47fa,{0xb4,0xbb,0x15,0x63,0x62,0xa2,0xf2,0x39}};
static const GUID IID_AsyncInfo={0x36,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID IID_MenuItem={0xf1c7c97f,0x78cc,0x5d1b,{0xaf,0x22,0xd0,0xef,0x18,0x14,0x6b,0xb0}};
static const GUID SID_MonitorManager={0x47094e3a,0x0cf2,0x430f,{0x80,0x6f,0xcf,0x9e,0x4f,0x0f,0x12,0xdd}};
static const GUID IID_MonitorManager={0x4d4c1e64,0xe410,0x4faa,{0xba,0xfa,0x59,0xca,0x06,0x9b,0xfe,0xc2}};
struct MonitorManager:IUnknown {
 virtual HRESULT STDMETHODCALLTYPE GetCount(UINT*)=0;
 virtual HRESULT STDMETHODCALLTYPE GetConnectedCount(UINT*)=0;
 virtual HRESULT STDMETHODCALLTYPE GetAt(UINT,IUnknown**)=0;
 virtual HRESULT STDMETHODCALLTYPE GetFromHandle(HMONITOR,IUnknown**)=0;
 virtual HRESULT STDMETHODCALLTYPE GetFromIdentity(DWORD,IUnknown**)=0;
 virtual HRESULT STDMETHODCALLTYPE GetImmersiveProxyMonitor(IUnknown**)=0;
 virtual HRESULT STDMETHODCALLTYPE QueryService(HMONITOR,REFGUID,REFIID,void**)=0;
 virtual HRESULT STDMETHODCALLTYPE QueryServiceByIdentity(DWORD,REFGUID,REFIID,void**)=0;
 virtual HRESULT STDMETHODCALLTYPE QueryServiceFromWindow(HWND,REFGUID,REFIID,void**)=0;
};
struct MenuItem; struct MenuVector;
struct AsyncInfo: IInspectable {
 virtual HRESULT STDMETHODCALLTYPE Id(UINT*)=0;
 virtual HRESULT STDMETHODCALLTYPE Status(INT*)=0;
 virtual HRESULT STDMETHODCALLTYPE Error(HRESULT*)=0;
 virtual HRESULT STDMETHODCALLTYPE Cancel()=0;
 virtual HRESULT STDMETHODCALLTYPE Close()=0;
};
struct AsyncResult: IInspectable {
 virtual HRESULT STDMETHODCALLTYPE PutCompleted(IUnknown*)=0;
 virtual HRESULT STDMETHODCALLTYPE GetCompleted(IUnknown**)=0;
 virtual HRESULT STDMETHODCALLTYPE Results(MenuVector**)=0;
};
struct AsyncAction: IInspectable {
 virtual HRESULT STDMETHODCALLTYPE PutCompleted(IUnknown*)=0;
 virtual HRESULT STDMETHODCALLTYPE GetCompleted(IUnknown**)=0;
 virtual HRESULT STDMETHODCALLTYPE Results()=0;
};
struct Tip: IUnknown {
 virtual HRESULT STDMETHODCALLTYPE Show(POINT*)=0;
 virtual HRESULT STDMETHODCALLTYPE Items(RECT,IUnknown**)=0;
};
struct MenuItem: IInspectable {
 virtual HRESULT STDMETHODCALLTYPE Id(HSTRING*)=0;
 virtual HRESULT STDMETHODCALLTYPE DisplayName(HSTRING*)=0;
 virtual HRESULT STDMETHODCALLTYPE FontIcon(IInspectable**)=0;
 virtual HRESULT STDMETHODCALLTYPE SetFontIcon(IInspectable*)=0;
 virtual HRESULT STDMETHODCALLTYPE Kind(INT*)=0;
 virtual HRESULT STDMETHODCALLTYPE SubItems(MenuVector**)=0;
 virtual HRESULT STDMETHODCALLTYPE Invoke(AsyncAction**)=0;
 virtual HRESULT STDMETHODCALLTYPE InvokeOptions(IInspectable*,AsyncAction**)=0;
 virtual HRESULT STDMETHODCALLTYPE States(UINT*)=0;
 virtual HRESULT STDMETHODCALLTYPE Bitmap(IInspectable**)=0;
 virtual HRESULT STDMETHODCALLTYPE AddInvoked(IUnknown*,INT64*)=0;
 virtual HRESULT STDMETHODCALLTYPE RemoveInvoked(INT64)=0;
 virtual HRESULT STDMETHODCALLTYPE Description(HSTRING*)=0;
 virtual HRESULT STDMETHODCALLTYPE SetDescription(HSTRING)=0;
};
struct MenuVector: IInspectable {
 virtual HRESULT STDMETHODCALLTYPE At(UINT,MenuItem**)=0;
 virtual HRESULT STDMETHODCALLTYPE Size(UINT*)=0;
 virtual HRESULT STDMETHODCALLTYPE IndexOf(MenuItem*,UINT*,BYTE*)=0;
 virtual HRESULT STDMETHODCALLTYPE GetMany(UINT,UINT,MenuItem**,UINT*)=0;
};
template<class T> struct Ref {
 T* p=nullptr; Ref(){} Ref(const Ref&)=delete; Ref& operator=(const Ref&)=delete;
 ~Ref(){if(p)p->Release();}
 T** out(){return &p;} T* operator->()const{return p;} operator bool()const{return p!=nullptr;}
};
struct Str {HSTRING h=nullptr;~Str(){WindowsDeleteString(h);} const wchar_t* text(){return WindowsGetStringRawBuffer(h,nullptr);}};
