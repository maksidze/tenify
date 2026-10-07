// Exact-build old Explorer -> native InputSwitch adapter. No disk patching.
// Initialization must be called outside DllMain in an owned entry-paused child.
#include <windows.h>
#include <objbase.h>
#include <bcrypt.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <new>
#include "Guards.h"

static const GUID CLSID_Control = {0xb9bc2a50,0x43c3,0x41aa,{0xa0,0x86,0x5d,0xb1,0x4e,0x18,0x4b,0xae}};
static const GUID IID_Control = {0xb9bc2a50,0x43c3,0x41aa,{0xa0,0x82,0x5d,0xb1,0x4e,0x18,0x4b,0xae}};
static const GUID IID_Callback = {0xb9bc2a50,0x43c3,0x41aa,{0xa0,0x83,0x5d,0xb1,0x4e,0x18,0x4b,0xae}};
static const GUID NativePdbGuid = {0xae60cb7f,0x0181,0x7dbe,{0x4e,0x43,0x23,0xad,0xd0,0xde,0xb0,0xa2}};

// Neutral names deliberately retain unknown private field semantics.
struct OldProfile {
    DWORD id; DWORD pad04;
    WCHAR *string08, *string10, *string18, *string20;
    DWORD flag28, flag2c, flag30, flag34;
    WCHAR *text38, *fontFace;
    DWORD scale, fontAdjustment, rotate, pad54;
    WCHAR *iconFile;
    DWORD iconIndex, pad64;
};
struct NativeProfile {
    DWORD id; DWORD pad04;
    WCHAR *string08, *string10, *string18, *string20;
    DWORD flag28, flag2c, flag30, flag34;
    DWORD newBoolean38, pad3c;
    WCHAR *text40, *fontFace;
    DWORD scale, fontAdjustment, rotate, pad5c;
    WCHAR *iconFile;
    DWORD iconIndex, pad6c;
};
struct OldIme { WCHAR* tooltip; HICON icon; BOOL disabled, hidden; WCHAR* glyph; };
struct NativeIme { WCHAR* tooltip; HICON icon; BOOL disabled, hidden; WCHAR* glyph; void* reserved20; };
static_assert(sizeof(OldProfile)==0x68 && sizeof(NativeProfile)==0x70, "profile ABI");
static_assert(offsetof(OldProfile,text38)==0x38 && offsetof(NativeProfile,text40)==0x40, "tail ABI");
static_assert(offsetof(OldProfile,rotate)==0x50 && offsetof(NativeProfile,rotate)==0x58, "font ABI");
static_assert(sizeof(OldIme)==0x20 && sizeof(NativeIme)==0x28, "IME ABI");

template<class Profile, class Ime> struct Callback : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE OnUpdateProfile(const Profile*)=0;
    virtual HRESULT STDMETHODCALLTYPE OnUpdateTsfFloatingFlags(DWORD)=0;
    virtual HRESULT STDMETHODCALLTYPE OnProfileCountChange(UINT,BOOL)=0;
    virtual HRESULT STDMETHODCALLTYPE OnShowHide(BOOL,BOOL,BOOL)=0;
    virtual HRESULT STDMETHODCALLTYPE OnImeModeItemUpdate(const Ime*)=0;
    virtual HRESULT STDMETHODCALLTYPE OnModalitySelected(int)=0;
    virtual HRESULT STDMETHODCALLTYPE OnContextFlagsChange(DWORD)=0;
    virtual HRESULT STDMETHODCALLTYPE OnTouchKeyboardManualInvoke()=0;
};
using OldCallback = Callback<OldProfile,OldIme>;
using NativeCallback = Callback<NativeProfile,NativeIme>;
struct OldControl : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Init(int)=0;
    virtual HRESULT STDMETHODCALLTYPE SetCallback(OldCallback*)=0;
    virtual HRESULT STDMETHODCALLTYPE ShowInputSwitch(const RECT*)=0;
    virtual HRESULT STDMETHODCALLTYPE GetProfileCount(UINT*,BOOL*)=0;
    virtual HRESULT STDMETHODCALLTYPE GetCurrentProfile(OldProfile*)=0;
    virtual HRESULT STDMETHODCALLTYPE RegisterHotkeys()=0;
    virtual HRESULT STDMETHODCALLTYPE ClickImeModeItem(int,POINT,const RECT*)=0;
    virtual HRESULT STDMETHODCALLTYPE ForceHide()=0;
    virtual HRESULT STDMETHODCALLTYPE ShowTouchKeyboardInputSwitch(const RECT*,int,int,DWORD,int)=0;
    virtual HRESULT STDMETHODCALLTYPE GetContextFlags(DWORD*)=0;
    virtual HRESULT STDMETHODCALLTYPE SetContextOverrideMode(int)=0;
    virtual HRESULT STDMETHODCALLTYPE GetCurrentImeModeItem(OldIme*)=0;
    virtual HRESULT STDMETHODCALLTYPE ActivateInputProfile(const WCHAR*)=0;
};
struct NativeControl : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Init(int)=0;
    virtual HRESULT STDMETHODCALLTYPE SetCallback(NativeCallback*)=0;
    virtual HRESULT STDMETHODCALLTYPE ShowInputSwitch(const RECT*)=0;
    virtual HRESULT STDMETHODCALLTYPE GetProfileCount(UINT*,BOOL*)=0;
    virtual HRESULT STDMETHODCALLTYPE GetCurrentProfile(NativeProfile*)=0;
    virtual HRESULT STDMETHODCALLTYPE RegisterHotkeys()=0;
    virtual HRESULT STDMETHODCALLTYPE ClickImeModeItem(int,POINT,const RECT*)=0;
    virtual HRESULT STDMETHODCALLTYPE ClickImeModeItemWithAnchor(int,IUnknown*)=0;
    virtual HRESULT STDMETHODCALLTYPE ForceHide()=0;
    virtual HRESULT STDMETHODCALLTYPE ShowTouchKeyboardInputSwitch(const RECT*,int,int,DWORD,int)=0;
    virtual HRESULT STDMETHODCALLTYPE GetContextFlags(DWORD*)=0;
    virtual HRESULT STDMETHODCALLTYPE SetContextOverrideMode(int)=0;
    virtual HRESULT STDMETHODCALLTYPE GetCurrentImeModeItem(NativeIme*)=0;
    virtual HRESULT STDMETHODCALLTYPE ActivateInputProfile(const WCHAR*)=0;
    virtual HRESULT STDMETHODCALLTYPE SetUserSid(const WCHAR*)=0;
};

extern "C" __declspec(dllexport) struct InputSwitchStats {
    DWORD version, installed, installError, wrappedControls;
    DWORD callbacks, profileQueries, imeQueries, rejectedNative;
    DWORD nativeScale, nativeRotate, oldScale, oldRotate, discardedBoolean;
    ULONG_PTR oldIat, newIat;
} InputSwitchCompatStats = {1};

static void ConvertProfile(const NativeProfile* src, OldProfile* dst) {
    // Caller owns src; this is a borrowed view or explicit ownership transfer.
    memcpy(dst,src,0x38);
    memcpy((BYTE*)dst+0x38,(const BYTE*)src+0x40,0x30);
    InputSwitchCompatStats.nativeScale=src->scale;
    InputSwitchCompatStats.nativeRotate=src->rotate;
    InputSwitchCompatStats.oldScale=dst->scale;
    InputSwitchCompatStats.oldRotate=dst->rotate;
    InputSwitchCompatStats.discardedBoolean=src->newBoolean38;
}
static void FreeNativeProfile(NativeProfile* p) {
    CoTaskMemFree(p->string08); CoTaskMemFree(p->string10);
    CoTaskMemFree(p->string18); CoTaskMemFree(p->string20);
    CoTaskMemFree(p->text40); CoTaskMemFree(p->fontFace); CoTaskMemFree(p->iconFile);
    ZeroMemory(p,sizeof(*p));
}
static void FreeOldProfile(OldProfile* p) {
    CoTaskMemFree(p->string08); CoTaskMemFree(p->string10);
    CoTaskMemFree(p->string18); CoTaskMemFree(p->string20);
    CoTaskMemFree(p->text38); CoTaskMemFree(p->fontFace); CoTaskMemFree(p->iconFile);
    ZeroMemory(p,sizeof(*p));
}
static void FreeNativeIme(NativeIme* p) {
    CoTaskMemFree(p->tooltip); if(p->icon) DestroyIcon(p->icon); CoTaskMemFree(p->glyph);
    // The exact guarded native CopyImeModeItemData always zeroes reserved20,
    // never reads/copies the source reserved20, and never releases it.
    ZeroMemory(p,sizeof(*p));
}
static void FreeOldIme(OldIme* p) {
    CoTaskMemFree(p->tooltip); if(p->icon) DestroyIcon(p->icon); CoTaskMemFree(p->glyph);
    ZeroMemory(p,sizeof(*p));
}

class CallbackProxy final : public NativeCallback {
    LONG refs=1;
    OldCallback* old;
public:
    explicit CallbackProxy(OldCallback* value):old(value) {old->AddRef();}
    ~CallbackProxy(){old->Release();}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
        if(!out)return E_POINTER; *out=nullptr;
        if(iid!=IID_IUnknown && iid!=IID_Callback)return E_NOINTERFACE;
        *out=static_cast<NativeCallback*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override {return InterlockedIncrement(&refs);}
    ULONG STDMETHODCALLTYPE Release() override {LONG n=InterlockedDecrement(&refs);if(!n)delete this;return n;}
    HRESULT STDMETHODCALLTYPE OnUpdateProfile(const NativeProfile* p) override {
        if(!p)return E_POINTER;
        OldProfile tmp; ConvertProfile(p,&tmp);
        InterlockedIncrement((LONG*)&InputSwitchCompatStats.callbacks);
        // Native callback caller frees original profile after this synchronous call.
        // Old _UpdateIndicatorInfo duplicates retained strings into its own state.
        return old->OnUpdateProfile(&tmp);
    }
    HRESULT STDMETHODCALLTYPE OnUpdateTsfFloatingFlags(DWORD a) override {return old->OnUpdateTsfFloatingFlags(a);}
    HRESULT STDMETHODCALLTYPE OnProfileCountChange(UINT a,BOOL b) override {return old->OnProfileCountChange(a,b);}
    HRESULT STDMETHODCALLTYPE OnShowHide(BOOL a,BOOL b,BOOL c) override {return old->OnShowHide(a,b,c);}
    HRESULT STDMETHODCALLTYPE OnImeModeItemUpdate(const NativeIme* p) override {
        if(!p)return E_POINTER; OldIme tmp;memcpy(&tmp,p,sizeof(tmp));
        return old->OnImeModeItemUpdate(&tmp); // Borrowed; never free icon/strings.
    }
    HRESULT STDMETHODCALLTYPE OnModalitySelected(int a) override {return old->OnModalitySelected(a);}
    HRESULT STDMETHODCALLTYPE OnContextFlagsChange(DWORD a) override {return old->OnContextFlagsChange(a);}
    HRESULT STDMETHODCALLTYPE OnTouchKeyboardManualInvoke() override {return old->OnTouchKeyboardManualInvoke();}
};

class ControlProxy final : public OldControl {
    LONG refs=1;
    NativeControl* native;
public:
    explicit ControlProxy(NativeControl* value):native(value) {} // Takes one existing ref.
    ~ControlProxy(){native->Release();}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
        if(!out)return E_POINTER; *out=nullptr;
        if(iid!=IID_IUnknown && iid!=IID_Control)return E_NOINTERFACE;
        *out=static_cast<OldControl*>(this);AddRef();return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override {return InterlockedIncrement(&refs);}
    ULONG STDMETHODCALLTYPE Release() override {LONG n=InterlockedDecrement(&refs);if(!n)delete this;return n;}
    HRESULT STDMETHODCALLTYPE Init(int a) override {return native->Init(a);}
    HRESULT STDMETHODCALLTYPE SetCallback(OldCallback* a) override {
        if(!a)return native->SetCallback(nullptr);
        auto* proxy=new(std::nothrow) CallbackProxy(a);if(!proxy)return E_OUTOFMEMORY;
        HRESULT hr=native->SetCallback(proxy);proxy->Release();return hr;
    }
    HRESULT STDMETHODCALLTYPE ShowInputSwitch(const RECT* a) override {return native->ShowInputSwitch(a);}
    HRESULT STDMETHODCALLTYPE GetProfileCount(UINT* a,BOOL* b) override {return native->GetProfileCount(a,b);}
    HRESULT STDMETHODCALLTYPE GetCurrentProfile(OldProfile* out) override {
        if(!out)return E_POINTER;ZeroMemory(out,sizeof(*out));NativeProfile tmp={};
        HRESULT hr=native->GetCurrentProfile(&tmp);
        if(SUCCEEDED(hr)){ConvertProfile(&tmp,out);ZeroMemory(&tmp,sizeof(tmp));}
        else FreeNativeProfile(&tmp);
        InterlockedIncrement((LONG*)&InputSwitchCompatStats.profileQueries);return hr;
    }
    HRESULT STDMETHODCALLTYPE RegisterHotkeys() override {return native->RegisterHotkeys();}
    HRESULT STDMETHODCALLTYPE ClickImeModeItem(int a,POINT b,const RECT* c) override {return native->ClickImeModeItem(a,b,c);}
    HRESULT STDMETHODCALLTYPE ForceHide() override {return native->ForceHide();}
    HRESULT STDMETHODCALLTYPE ShowTouchKeyboardInputSwitch(const RECT* a,int b,int c,DWORD d,int e) override {return native->ShowTouchKeyboardInputSwitch(a,b,c,d,e);}
    HRESULT STDMETHODCALLTYPE GetContextFlags(DWORD* a) override {return native->GetContextFlags(a);}
    HRESULT STDMETHODCALLTYPE SetContextOverrideMode(int a) override {return native->SetContextOverrideMode(a);}
    HRESULT STDMETHODCALLTYPE GetCurrentImeModeItem(OldIme* out) override {
        if(!out)return E_POINTER;ZeroMemory(out,sizeof(*out));NativeIme tmp={};
        HRESULT hr=native->GetCurrentImeModeItem(&tmp);
        if(SUCCEEDED(hr)){memcpy(out,&tmp,sizeof(*out));ZeroMemory(&tmp,sizeof(tmp));}
        else FreeNativeIme(&tmp);
        InterlockedIncrement((LONG*)&InputSwitchCompatStats.imeQueries);return hr;
    }
    HRESULT STDMETHODCALLTYPE ActivateInputProfile(const WCHAR* a) override {return native->ActivateInputProfile(a);}
};

static bool HashFile(const WCHAR* path,const BYTE expected[32]) {
    HANDLE f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(f==INVALID_HANDLE_VALUE)return false;
    BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;BYTE digest[32],buf[32768];DWORD read=0;bool ok=false;
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0 && BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0)>=0){
        ok=true;
        for(;;){
            if(!ReadFile(f,buf,sizeof(buf),&read,nullptr)){ok=false;break;}
            if(!read)break;
            if(BCryptHashData(hash,buf,read,0)<0){ok=false;break;}
        }
        if(BCryptFinishHash(hash,digest,sizeof(digest),0)<0)ok=false;
        if(ok)ok=memcmp(digest,expected,32)==0;
    }
    if(hash)BCryptDestroyHash(hash);if(alg)BCryptCloseAlgorithmProvider(alg,0);CloseHandle(f);return ok;
}
static bool CheckCode(BYTE* base,const CodeGuard* guards,size_t count) {
    for(size_t i=0;i<count;i++)if(memcmp(base+guards[i].rva,guards[i].bytes,guards[i].length))return false;
    return true;
}
static bool CheckPdb(BYTE* base) {
    auto* dos=(IMAGE_DOS_HEADER*)base;auto* nt=(IMAGE_NT_HEADERS64*)(base+dos->e_lfanew);
    auto dir=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    auto* records=(IMAGE_DEBUG_DIRECTORY*)(base+dir.VirtualAddress);
    for(DWORD i=0;i<dir.Size/sizeof(*records);i++){
        if(records[i].Type!=IMAGE_DEBUG_TYPE_CODEVIEW||records[i].SizeOfData<24)continue;
        BYTE* data=base+records[i].AddressOfRawData;
        if(!memcmp(data,"RSDS",4)&&!memcmp(data+4,&NativePdbGuid,16)&&*(DWORD*)(data+20)==1)return true;
    }
    return false;
}
static bool NativeFileVerified() {
    WCHAR path[MAX_PATH];UINT n=GetSystemDirectoryW(path,MAX_PATH);
    if(!n||n>MAX_PATH-17)return false;wcscat(path,L"\\InputSwitch.dll");
    return HashFile(path,ExpectedNativeHash);
}
static bool NativeObjectVerified(NativeControl* object) {
    if(!object)return false;HMODULE module=nullptr;void** table=*(void***)object;
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(LPCWSTR)table,&module))return false;
    WCHAR actual[MAX_PATH],expected[MAX_PATH];bool ok=false;
    if(GetModuleFileNameW(module,actual,MAX_PATH)&&GetSystemDirectoryW(expected,MAX_PATH)){
        wcscat(expected,L"\\InputSwitch.dll");BYTE* b=(BYTE*)module;
        ok=!_wcsicmp(actual,expected) && table==(void**)(b+NativeVtableRva) && CheckPdb(b)
           && CheckCode(b,NativeGuards,sizeof(NativeGuards)/sizeof(*NativeGuards));
        for(size_t i=0;ok&&i<18;i++)ok=table[i]==b+NativeMethodRvas[i];
    }
    FreeLibrary(module);return ok;
}
using CreateInstance = HRESULT (WINAPI*)(REFCLSID,LPUNKNOWN,DWORD,REFIID,LPVOID*);
static CreateInstance OriginalCoCreate=nullptr;
static BYTE* ExplorerBase=nullptr;
static HRESULT WINAPI HookCoCreate(REFCLSID clsid,LPUNKNOWN outer,DWORD context,REFIID iid,LPVOID* out) {
    bool adapt=(BYTE*)__builtin_return_address(0)==ExplorerBase+ScopedReturnRva && !outer && clsid==CLSID_Control && iid==IID_Control;
    HRESULT hr=OriginalCoCreate(clsid,outer,context,iid,out);
    if(!adapt||FAILED(hr))return hr;
    if(!out||!*out)return E_UNEXPECTED;
    auto* native=(NativeControl*)*out;
    if(!NativeObjectVerified(native)){
        native->Release();*out=nullptr;InterlockedIncrement((LONG*)&InputSwitchCompatStats.rejectedNative);
        return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
    }
    auto* proxy=new(std::nothrow) ControlProxy(native);
    if(!proxy){native->Release();*out=nullptr;return E_OUTOFMEMORY;}
    *out=static_cast<OldControl*>(proxy);
    InterlockedIncrement((LONG*)&InputSwitchCompatStats.wrappedControls);
    OutputDebugStringW(L"InputSwitchCompat: exact old control proxy created; 16->18 slots, profile104->112.\n");
    return hr;
}
extern "C" __declspec(dllexport) DWORD WINAPI InputSwitchCompatInitialize(void*) {
    if(InputSwitchCompatStats.installed){
        return ExplorerBase && *(void**)(ExplorerBase+CoCreateIatRva)==(void*)&HookCoCreate
            ? ERROR_SUCCESS : ERROR_INVALID_ADDRESS;
    }
    WCHAR mainPath[MAX_PATH];BYTE* main=(BYTE*)GetModuleHandleW(nullptr);
    DWORD error=ERROR_REVISION_MISMATCH;
    if(!GetModuleFileNameW(nullptr,mainPath,MAX_PATH) || !HashFile(mainPath,ExpectedExeHash)
       || !NativeFileVerified() || !CheckCode(main,OldGuards,sizeof(OldGuards)/sizeof(*OldGuards)))goto failed;
    {
        auto** slot=(void**)(main+CoCreateIatRva);
        void* real=(void*)GetProcAddress(GetModuleHandleW(L"ole32.dll"),"CoCreateInstance");
        // Deliberately refuse unknown prior IAT hooks. Integrator must coordinate order.
        if(!real||*slot!=real){error=ERROR_INVALID_ADDRESS;goto failed;}
        // Pin this DLL: wrappers and IAT function pointers remain valid for process life.
        HMODULE self=nullptr;
        if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(LPCWSTR)&HookCoCreate,&self)){error=GetLastError();goto failed;}
        DWORD oldProtect=0;
        if(!VirtualProtect(slot,sizeof(*slot),PAGE_READWRITE,&oldProtect)){error=GetLastError();goto failed;}
        OriginalCoCreate=(CreateInstance)real;ExplorerBase=main;
        void* previous=InterlockedCompareExchangePointer(slot,(void*)&HookCoCreate,real);
        bool readback=*slot==(void*)&HookCoCreate;
        DWORD ignored=0;BOOL restored=VirtualProtect(slot,sizeof(*slot),oldProtect,&ignored);
        if(previous!=real || !readback || !restored){
            // Owned launcher must terminate child on any nonzero return.
            error=ERROR_WRITE_FAULT;goto failed;
        }
        InputSwitchCompatStats.oldIat=(ULONG_PTR)real;InputSwitchCompatStats.newIat=(ULONG_PTR)*slot;
        InputSwitchCompatStats.installed=1;
        OutputDebugStringW(L"InputSwitchCompat: SHA/PDB/instruction guards PASS; scoped IAT readback PASS.\n");
        return ERROR_SUCCESS;
    }
failed:
    InputSwitchCompatStats.installError=error;return error;
}

#ifdef INPUTSWITCH_PROBE
static WCHAR* Dup(const WCHAR* s){size_t n=(wcslen(s)+1)*sizeof(WCHAR);auto* p=(WCHAR*)CoTaskMemAlloc(n);if(p)memcpy(p,s,n);return p;}
static int failures=0;
#define CHECK(x) do{if(!(x)){printf("FAIL line=%d expression=%s\n",__LINE__,#x);failures++;}}while(0)
class FakeCallback final:public OldCallback {
public:
    LONG refs=1;int last=-1;OldProfile profile={};OldIme ime={};
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** p)override{if(!p)return E_POINTER;*p=nullptr;if(iid!=IID_IUnknown&&iid!=IID_Callback)return E_NOINTERFACE;*p=this;AddRef();return S_OK;}
    ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;} ULONG STDMETHODCALLTYPE Release()override{return --refs;}
    HRESULT STDMETHODCALLTYPE OnUpdateProfile(const OldProfile* p)override{last=3;profile=*p;return S_OK;}
    HRESULT STDMETHODCALLTYPE OnUpdateTsfFloatingFlags(DWORD a)override{CHECK(a==1);last=4;return S_OK;}
    HRESULT STDMETHODCALLTYPE OnProfileCountChange(UINT a,BOOL b)override{CHECK(a==2&&b==1);last=5;return S_OK;}
    HRESULT STDMETHODCALLTYPE OnShowHide(BOOL a,BOOL b,BOOL c)override{CHECK(a==1&&b==2&&c==3);last=6;return S_OK;}
    HRESULT STDMETHODCALLTYPE OnImeModeItemUpdate(const OldIme* p)override{last=7;ime=*p;return S_OK;}
    HRESULT STDMETHODCALLTYPE OnModalitySelected(int a)override{CHECK(a==1);last=8;return S_OK;}
    HRESULT STDMETHODCALLTYPE OnContextFlagsChange(DWORD a)override{CHECK(a==1);last=9;return S_OK;}
    HRESULT STDMETHODCALLTYPE OnTouchKeyboardManualInvoke()override{last=10;return S_OK;}
};
class FakeControl final:public NativeControl {
public:
    LONG refs=1;int last=-1;NativeCallback* cb=nullptr;HRESULT profileResult=S_OK,imeResult=S_OK;const RECT* expectedRect=nullptr;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** p)override{if(!p)return E_POINTER;*p=nullptr;if(iid!=IID_IUnknown&&iid!=IID_Control)return E_NOINTERFACE;*p=this;AddRef();return S_OK;}
    ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{return --refs;}
    HRESULT STDMETHODCALLTYPE Init(int a)override{CHECK(a==0);last=3;return S_OK;}
    HRESULT STDMETHODCALLTYPE SetCallback(NativeCallback* p)override{if(p)p->AddRef();if(cb)cb->Release();cb=p;last=4;return S_OK;}
    HRESULT STDMETHODCALLTYPE ShowInputSwitch(const RECT* a)override{CHECK(a==expectedRect);last=5;return S_OK;}
    HRESULT STDMETHODCALLTYPE GetProfileCount(UINT* a,BOOL* b)override{last=6;*a=2;*b=FALSE;return S_OK;}
    HRESULT STDMETHODCALLTYPE GetCurrentProfile(NativeProfile* p)override{
        last=7;ZeroMemory(p,sizeof(*p));p->id=0x419;p->string08=Dup(L"08");p->string10=Dup(L"10");p->string18=Dup(L"18");p->string20=Dup(L"20");
        p->flag28=28;p->flag2c=44;p->flag30=48;p->flag34=52;p->newBoolean38=1;p->text40=Dup(L"RUS");p->fontFace=Dup(L"Segoe UI");
        p->scale=100;p->fontAdjustment=123;p->rotate=0;p->iconFile=Dup(L"icon.dll");p->iconIndex=7;return profileResult;
    }
    HRESULT STDMETHODCALLTYPE RegisterHotkeys()override{last=8;return S_OK;}
    HRESULT STDMETHODCALLTYPE ClickImeModeItem(int a,POINT b,const RECT* c)override{CHECK(a==0&&b.x==12&&b.y==34&&c==expectedRect);last=9;return S_OK;}
    HRESULT STDMETHODCALLTYPE ClickImeModeItemWithAnchor(int,IUnknown*)override{last=10;return S_OK;}
    HRESULT STDMETHODCALLTYPE ForceHide()override{last=11;return S_OK;}
    HRESULT STDMETHODCALLTYPE ShowTouchKeyboardInputSwitch(const RECT* a,int b,int c,DWORD d,int e)override{CHECK(a==expectedRect&&b==0&&c==1&&d==2&&e==3);last=12;return S_OK;}
    HRESULT STDMETHODCALLTYPE GetContextFlags(DWORD* a)override{last=13;*a=0x1234;return S_OK;}
    HRESULT STDMETHODCALLTYPE SetContextOverrideMode(int a)override{CHECK(a==0);last=14;return S_OK;}
    HRESULT STDMETHODCALLTYPE GetCurrentImeModeItem(NativeIme* p)override{last=15;ZeroMemory(p,sizeof(*p));p->tooltip=Dup(L"tip");p->glyph=Dup(L"A");p->disabled=1;p->hidden=2;return imeResult;}
    HRESULT STDMETHODCALLTYPE ActivateInputProfile(const WCHAR* a)override{CHECK(a&&!wcscmp(a,L"fixture"));last=16;return S_OK;}
    HRESULT STDMETHODCALLTYPE SetUserSid(const WCHAR*)override{last=17;return S_OK;}
};
static int Fixtures(){
    FakeControl fake;OldControl* c=new(std::nothrow) ControlProxy(&fake);CHECK(c);if(!c)return 1;
    void* qi=nullptr;CHECK(c->QueryInterface(IID_Control,&qi)==S_OK&&qi==c);((IUnknown*)qi)->Release();
    CHECK(c->QueryInterface(IID_IUnknown,&qi)==S_OK&&qi==c);((IUnknown*)qi)->Release();
    CHECK(c->QueryInterface(IID_IDispatch,&qi)==E_NOINTERFACE&&qi==nullptr);
    NativeProfile everyByte;for(size_t i=0;i<sizeof(everyByte);i++)((BYTE*)&everyByte)[i]=(BYTE)(i+1);
    OldProfile byteMapped;ConvertProfile(&everyByte,&byteMapped);
    CHECK(!memcmp(&byteMapped,&everyByte,0x38)&&!memcmp((BYTE*)&byteMapped+0x38,(BYTE*)&everyByte+0x40,0x30));
    c->Init(0);CHECK(fake.last==3);RECT r={};fake.expectedRect=&r;POINT point={12,34};UINT count;BOOL flag;
    c->ShowInputSwitch(&r);CHECK(fake.last==5);c->GetProfileCount(&count,&flag);CHECK(fake.last==6&&count==2);
    struct GuardProfile{ULONGLONG before;OldProfile p;ULONGLONG after;}g={0xdeadbeef,{},0xabcdef01};
    CHECK(c->GetCurrentProfile(&g.p)==S_OK);CHECK(g.before==0xdeadbeef&&g.after==0xabcdef01);
    CHECK(g.p.scale==100&&g.p.rotate==0&&g.p.fontAdjustment==123&&g.p.iconIndex==7);
    CHECK(!wcscmp(g.p.fontFace,L"Segoe UI")&&!wcscmp(g.p.text38,L"RUS")&&!wcscmp(g.p.iconFile,L"icon.dll"));
    CHECK(g.p.flag28==28&&g.p.flag2c==44&&g.p.flag30==48&&g.p.flag34==52);
    CHECK(!wcscmp(g.p.string08,L"08")&&!wcscmp(g.p.string10,L"10")&&!wcscmp(g.p.string18,L"18")&&!wcscmp(g.p.string20,L"20"));
    LOGFONTW lf={};lf.lfEscapement=lf.lfOrientation=g.p.rotate?2700:0;CHECK(lf.lfEscapement==0&&lf.lfOrientation==0);FreeOldProfile(&g.p);
    fake.profileResult=E_FAIL;CHECK(c->GetCurrentProfile(&g.p)==E_FAIL&&!g.p.string08&&!g.p.iconFile);CHECK(g.after==0xabcdef01);fake.profileResult=S_OK;
    c->RegisterHotkeys();CHECK(fake.last==8);c->ClickImeModeItem(0,point,&r);CHECK(fake.last==9);
    c->ForceHide();CHECK(fake.last==11);c->ShowTouchKeyboardInputSwitch(&r,0,1,2,3);CHECK(fake.last==12);
    DWORD context=0;c->GetContextFlags(&context);CHECK(fake.last==13&&context==0x1234);c->SetContextOverrideMode(0);CHECK(fake.last==14);
    struct GuardIme{ULONGLONG before;OldIme p;ULONGLONG after;}im={0xdeadbeef,{},0xabcdef01};
    CHECK(c->GetCurrentImeModeItem(&im.p)==S_OK&&fake.last==15&&im.p.disabled==1&&im.p.hidden==2);CHECK(im.before==0xdeadbeef&&im.after==0xabcdef01);FreeOldIme(&im.p);
    fake.imeResult=E_FAIL;CHECK(c->GetCurrentImeModeItem(&im.p)==E_FAIL&&!im.p.tooltip&&!im.p.glyph);CHECK(im.after==0xabcdef01);
    c->ActivateInputProfile(L"fixture");CHECK(fake.last==16);
    FakeCallback cb;c->SetCallback(&cb);CHECK(cb.refs==2&&fake.cb);
    CHECK(fake.cb->QueryInterface(IID_Callback,&qi)==S_OK&&qi==fake.cb);((IUnknown*)qi)->Release();
    CHECK(fake.cb->QueryInterface(IID_Control,&qi)==E_NOINTERFACE&&qi==nullptr);
    NativeProfile np={};np.scale=100;np.newBoolean38=1;np.rotate=0;np.fontFace=(WCHAR*)L"borrowed";np.text40=(WCHAR*)L"RUS";
    fake.cb->OnUpdateProfile(&np);CHECK(cb.last==3&&cb.profile.scale==100&&cb.profile.rotate==0&&cb.profile.fontFace==np.fontFace);
    np.rotate=1;fake.cb->OnUpdateProfile(&np);lf.lfEscapement=lf.lfOrientation=cb.profile.rotate?2700:0;CHECK(lf.lfOrientation==2700);
    fake.cb->OnUpdateTsfFloatingFlags(1);CHECK(cb.last==4);fake.cb->OnProfileCountChange(2,1);CHECK(cb.last==5);fake.cb->OnShowHide(1,2,3);CHECK(cb.last==6);
    NativeIme ni={};ni.tooltip=(WCHAR*)L"borrowed tip";ni.glyph=(WCHAR*)L"A";ni.reserved20=(void*)0x1234;fake.cb->OnImeModeItemUpdate(&ni);CHECK(cb.last==7&&cb.ime.tooltip==ni.tooltip);
    fake.cb->OnModalitySelected(1);CHECK(cb.last==8);fake.cb->OnContextFlagsChange(1);CHECK(cb.last==9);fake.cb->OnTouchKeyboardManualInvoke();CHECK(cb.last==10);
    c->SetCallback(nullptr);CHECK(cb.refs==1&&!fake.cb);c->Release();CHECK(fake.refs==0);
    printf("{\"fixture\":\"%s\",\"failures\":%d,\"controlSlots\":16,\"nativeSlots\":18,\"callbackSlots\":11,\"profileCanary\":true,\"imeCanary\":true}\n",failures?"FAIL":"PASS",failures);return failures?1:0;
}
static int NativeQuery(){
    WCHAR desktopName[80];swprintf(desktopName,80,L"InputSwitchReadOnly-%lu",GetCurrentProcessId());
    HDESK original=GetThreadDesktop(GetCurrentThreadId());HDESK hidden=CreateDesktopW(desktopName,nullptr,nullptr,0,GENERIC_ALL,nullptr);
    if(!hidden||!SetThreadDesktop(hidden)){printf("desktop error=%lu\n",GetLastError());if(hidden)CloseDesktop(hidden);return 2;}
    HRESULT co=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);printf("CoInitialize hr=%08lx\n",(ULONG)co);
    if(FAILED(co)){SetThreadDesktop(original);CloseDesktop(hidden);return 3;}
    int result=4;NativeControl* native=nullptr;
    HRESULT hr=NativeFileVerified()?CoCreateInstance(CLSID_Control,nullptr,CLSCTX_INPROC_SERVER,IID_Control,(void**)&native):HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
    printf("CoCreate hr=%08lx pid=%lu hiddenDesktop=true\n",(ULONG)hr,GetCurrentProcessId());
    if(SUCCEEDED(hr)){
        bool verified=NativeObjectVerified(native);printf("nativeGuards=%s\n",verified?"PASS":"FAIL");
        if(verified){
            hr=native->Init(0);printf("Init hr=%08lx\n",(ULONG)hr);
            if(SUCCEEDED(hr)){
                NativeProfile p={};HRESULT ph=native->GetCurrentProfile(&p);
                printf("NativeProfile hr=%08lx id=%08lx flag38=%lu scale=%lu adjustment=%lu rotate=%lu iconIndex=%lu\n",(ULONG)ph,p.id,p.newBoolean38,p.scale,p.fontAdjustment,p.rotate,p.iconIndex);
                if(SUCCEEDED(ph)){
                    OldProfile old={};ConvertProfile(&p,&old);
                    printf("ConvertedProfile scale=%lu adjustment=%lu rotate=%lu fontAngle=%d fontFacePresent=%d textPresent=%d\n",old.scale,old.fontAdjustment,old.rotate,old.rotate?2700:0,old.fontFace!=nullptr,old.text38!=nullptr);
                    // ConvertProfile above was a borrowed inspection only; native owns/frees here.
                    result=old.scale==p.scale&&old.rotate==p.rotate?0:5;
                }
                FreeNativeProfile(&p);
                NativeIme im={};HRESULT ih=native->GetCurrentImeModeItem(&im);printf("NativeIme hr=%08lx reserved20=%p\n",(ULONG)ih,im.reserved20);FreeNativeIme(&im);
                DWORD flags=0;HRESULT fh=native->GetContextFlags(&flags);printf("NativeContext hr=%08lx flags=%08lx\n",(ULONG)fh,flags);
                native->AddRef();OldControl* proxy=new(std::nothrow) ControlProxy(native);
                if(!proxy){native->Release();result=6;}
                else {
                    struct {ULONGLONG before;OldProfile data;ULONGLONG after;} pg={0x1020304050607080,{},0x8877665544332211};
                    struct {ULONGLONG before;OldIme data;ULONGLONG after;} ig={0x1020304050607080,{},0x8877665544332211};
                    HRESULT php=proxy->GetCurrentProfile(&pg.data),ihp=proxy->GetCurrentImeModeItem(&ig.data);
                    DWORD flags2=0;HRESULT fhp=proxy->GetContextFlags(&flags2);
                    bool canaries=pg.before==0x1020304050607080&&pg.after==0x8877665544332211&&ig.before==0x1020304050607080&&ig.after==0x8877665544332211;
                    printf("RealProxy profile=%08lx ime=%08lx context=%08lx flags=%08lx scale=%lu rotate=%lu canaries=%s\n",(ULONG)php,(ULONG)ihp,(ULONG)fhp,flags2,pg.data.scale,pg.data.rotate,canaries?"PASS":"FAIL");
                    if(FAILED(php)||FAILED(ihp)||FAILED(fhp)||flags2!=flags||!canaries)result=7;
                    FreeOldProfile(&pg.data);FreeOldIme(&ig.data);proxy->Release();
                }
            }
        }
        native->SetCallback(nullptr);native->Release();
    }
    CoUninitialize();BOOL reset=SetThreadDesktop(original);DWORD resetError=reset?0:GetLastError();BOOL closed=CloseDesktop(hidden);DWORD closeError=closed?0:GetLastError();
    // InputSwitch can retain native per-thread hidden windows until process exit.
    // Outer supervisor checks that this exact child and its desktop are gone.
    printf("cleanup CoUninitialize=true desktopReset=%d resetError=%lu desktopClose=%d closeError=%lu processExitCleanupRequired=%d result=%d\n",reset,resetError,closed,closeError,!closed,result);return result;
}
int wmain(int argc,wchar_t** argv){setvbuf(stdout,nullptr,_IONBF,0);if(argc==2&&!wcscmp(argv[1],L"--native-query"))return NativeQuery();if(argc==2&&!wcscmp(argv[1],L"--fixtures"))return Fixtures();return 64;}
#endif
