from pathlib import Path
import subprocess,json
root=Path.cwd()
lab=root/'outputs/Windows10-Components/Lab/ViewDelegateCompat'
s=(lab/'ViewDelegateHookProbe.c').read_text()
needle='static HRESULT WINAPI invoke(Callback *s,void *sender,void *args)'
start=s.index(needle);end=s.index('static void *vt[]=',start)
s=s[:start]+r'''
static const GUID senderIID={0xf4a53d68,0x890b,0x4931,{0xbd,0xbf,0x71,0x15,0x83,0x77,0xee,0xce}};
static const GUID argsIID={0x96c11dea,0x68de,0x44ef,{0xa7,0xf7,0x3a,0xa8,0x69,0x66,0x3d,0x57}};
static const GUID inspectableIID={0xaf86e2e0,0xb12d,0x4c6a,{0x9c,0x5a,0xd7,0xaa,0x65,0x10,0x1e,0x90}};
typedef struct TestArgument{void **vt;LONG refs;const GUID *iid;unsigned kind;} TestArgument;
static volatile LONG argumentCalls[2];static APTTYPE argumentApartments[2];static DWORD argumentThreads[2];
static HRESULT WINAPI argQuery(TestArgument *s,const GUID *iid,void **out){
 *out=NULL;if(IsEqualGUID(iid,&IID_IUnknown)||IsEqualGUID(iid,&inspectableIID)||IsEqualGUID(iid,s->iid)){*out=s;InterlockedIncrement(&s->refs);return S_OK;}return E_NOINTERFACE;
}
static ULONG WINAPI argAdd(TestArgument *s){return InterlockedIncrement(&s->refs);}
static ULONG WINAPI argRelease(TestArgument *s){return InterlockedDecrement(&s->refs);}
static HRESULT WINAPI argIids(TestArgument *s,ULONG *count,GUID **out){
 *count=0;*out=CoTaskMemAlloc(sizeof(GUID));if(!*out)return E_OUTOFMEMORY;**out=*s->iid;*count=1;return S_OK;
}
static HRESULT WINAPI argName(TestArgument *s,void **out){*out=NULL;return S_OK;}
static HRESULT WINAPI argTrust(TestArgument *s,INT *trust){
 APTTYPEQUALIFIER q;HRESULT hr=CoGetApartmentType(&argumentApartments[s->kind],&q);
 argumentThreads[s->kind]=GetCurrentThreadId();InterlockedIncrement(&argumentCalls[s->kind]);*trust=2;return hr;
}
// This fixture tests the exact IID and inherited IInspectable RPC path only.
// App-specific ViewWrapper/EventArgs property methods are deliberately absent.
static void *argVt[]={argQuery,argAdd,argRelease,argIids,argName,argTrust};
static HRESULT WINAPI inspectArgument(void *p,const GUID *iid){
 if(!p)return E_POINTER;void *typed=NULL;
 HRESULT hr=((HRESULT(WINAPI*)(void*,const GUID*,void**))(*(void***)p)[0])(p,iid,&typed);
 if(FAILED(hr))return hr;ULONG count=0;GUID *ids=NULL;
 hr=((HRESULT(WINAPI*)(void*,ULONG*,GUID**))(*(void***)typed)[3])(typed,&count,&ids);
 if(SUCCEEDED(hr)&& (count!=1||!ids||!IsEqualGUID(ids,iid)))hr=E_FAIL;
 CoTaskMemFree(ids);INT trust=-1;if(SUCCEEDED(hr))hr=((HRESULT(WINAPI*)(void*,INT*))(*(void***)typed)[5])(typed,&trust);
 if(SUCCEEDED(hr)&&trust!=2)hr=E_FAIL;
 ((ULONG(WINAPI*)(void*))(*(void***)typed)[2])(typed);return hr;
}
static HRESULT WINAPI invoke(Callback *s,void *sender,void *args){
 invokeThread=GetCurrentThreadId();InterlockedIncrement(&calls);
 if(invokeThread!=ownerThread)return E_FAIL;
 HRESULT hr=inspectArgument(sender,&senderIID);if(SUCCEEDED(hr))hr=inspectArgument(args,&argsIID);return hr;
}
''' +s[end:]
start=s.index('static DWORD WINAPI other(');end=s.index('int wmain(',start)
s=s[:start]+r'''static DWORD WINAPI other(void *unused){
 CoInitializeEx(NULL,COINIT_MULTITHREADED);void *callback=NULL;
 CLSID got={0};void *ps=NULL;HRESULT ph=CoGetPSClsid(&senderIID,&got);
 HRESULT fh=CoGetClassObject(&got,CLSCTX_INPROC_SERVER,NULL,&ipsIID,&ps);
 fprintf(log,"MTA sender PS mapping=%08lx factory=%08lx ptr=%p\n",ph,fh,ps);fflush(log);
 if(ps)((ULONG(WINAPI*)(void*))(*(void***)ps)[2])(ps);
 TestArgument sender={argVt,1,&senderIID,0},args={argVt,1,&argsIID,1};
 resolved=((RESOLVE)(*(void***)agile)[3])(agile,&delegateIID,&callback);
 if(SUCCEEDED(resolved)){
  invoked=((HRESULT(WINAPI*)(void*,void*,void*))(*(void***)callback)[3])(callback,&sender,&args);
  ((ULONG(WINAPI*)(void*))(*(void***)callback)[2])(callback);
 }
 SetEvent(done);CoUninitialize();return 0;
}
'''+s[end:]
s=s.replace('BOOL pass=SUCCEEDED(resolved)',r'''fprintf(log,"NonNULL sender: calls=%ld apartment=%d thread=%lu; args: calls=%ld apartment=%d thread=%lu\n",argumentCalls[0],argumentApartments[0],argumentThreads[0],argumentCalls[1],argumentApartments[1],argumentThreads[1]);
 BOOL nonnull=argumentCalls[0]==1&&argumentCalls[1]==1&&argumentApartments[0]==APTTYPE_MTA&&argumentApartments[1]==APTTYPE_MTA&&argumentThreads[0]!=ownerThread&&argumentThreads[1]!=ownerThread;
 BOOL pass=nonnull&&SUCCEEDED(resolved)''')
# Replacement text is ordinary C source. Keep intended C newline, not a doubled
# slash produced by a Python raw string's formatting template.
s=s.replace('thread=%lu\\\\n','thread=%lu\\n')
(lab/'ViewDelegateNonNullProbe.c').write_text(s)
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1','-g',str(lab/'ViewDelegateNonNullProbe.c'),'-o',str(lab/'ViewDelegateNonNullProbe.exe'),'-lole32','-luuid'],check=True)
report=lab/'nonnull-probe.log'
child=subprocess.Popen([str(lab/'ViewDelegateNonNullProbe.exe'),str(report),str(lab/'ViewDelegateProxy.dll')],creationflags=subprocess.CREATE_NO_WINDOW)
try:
 code=child.wait(timeout=15)
except subprocess.TimeoutExpired:
 child.kill();child.wait();raise
print(report.read_text())
assert code==0
(lab/'nonnull-result.json').write_text(json.dumps({'pass':True,'test':'Non-agile exact old delegate STA; nonNULL exact old ViewWrapper/EventArgs IIDs MTA; typed QI/GetIids/GetTrustLevel via genuine old COM proxy','systemFilesChanged':False,'registryChanged':False,'explorerOrSEHStarted':False,'limitations':'Synthetic objects exercise inherited IInspectable methods; real ViewWrapper/EventArgs property methods and shell lifetime remain untested.'},indent=2))
