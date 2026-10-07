from pathlib import Path
import json,subprocess,hashlib
X=Path(__file__).resolve().parent;H=X.parent/'SettingsNoVfsCompat';D=X.parent/'SettingsNoVfsDiagnostics'
(X/'FactoryPins.h').write_bytes((H/'FactoryPins.h').read_bytes())
trace=json.loads((X.parent/'SettingsNoVfsSessionCompat/sessions/5f18cf5ce58f40a2a2c25b577f7cbf37/factory-diagnostic-10712.json').read_text())
names=sorted(set(r['Class'] for r in trace['StableRows'] if r['Route']==4))
declaration='static const WCHAR* observedNames[]={'+','.join('L"'+n+'"' for n in names)+'};\n'
probe=r'''
static bool checkXaml(){
 HMODULE xaml=GetModuleHandleW(L"Windows.UI.Xaml.dll");auto ro=(HRESULT(WINAPI*)(HSTRING,REFIID,void**))*(void**)((BYTE*)xaml+0x105e448);auto ra=(HRESULT(WINAPI*)(HSTRING,IInspectable**))*(void**)((BYTE*)xaml+0x105e438);
 const GUID privateIID={0x60d27c8d,0x5f61,0x4cce,{0xb7,0x51,0x69,0x0f,0xae,0x66,0xaa,0x53}};bool pass=true;
 for(auto name:observedNames){HSTRING s;WindowsCreateString(name,(UINT)wcslen(name),&s);IActivationFactory*factory=nullptr;HRESULT found=REGDB_E_CLASSNOTREG;for(auto module:{L"SystemSettingsViewModel.Desktop.dll",L"Telemetry.Common.dll",L"SystemSettings.dll"}){auto get=(HRESULT(WINAPI*)(HSTRING,IActivationFactory**))GetProcAddress(GetModuleHandleW(module),"DllGetActivationFactory");found=get?get(s,&factory):REGDB_E_CLASSNOTREG;if(SUCCEEDED(found)&&factory)break;}
  for(const GUID*i:{&privateIID,&__uuidof(IActivationFactory)}){struct{ULONGLONG pre;void*out;ULONGLONG post;}o={0x1234567812345678ULL,(void*)1,0x8765432187654321ULL};void*expected=nullptr;HRESULT want=factory?factory->QueryInterface(*i,&expected):found;HRESULT actual=ro(s,*i,&o.out);WCHAR owner[32768]=L"none";if(SUCCEEDED(actual)&&o.out){HMODULE m;if(GetModuleHandleExW(6,(PCWSTR)*(void**)o.out,&m))GetModuleFileNameW(m,owner,32768);}
  bool ok=factory&&actual==want&&o.pre==0x1234567812345678ULL&&o.post==0x8765432187654321ULL&&((FAILED(actual)&&!o.out)||(SUCCEEDED(actual)&&o.out&&wcsstr(owner,L"\\Image\\4\\")));fwprintf(f,L"XAML_TYPED\t%ls\t%08lx\t%08lx\t%u\t%ls\n",name,want,actual,ok,owner);fflush(f);pass&=ok;if(expected)((IUnknown*)expected)->Release();if(SUCCEEDED(actual)&&o.out)((IUnknown*)o.out)->Release();}
  if(factory)factory->Release();WindowsDeleteString(s);
 }
 HSTRING s;WindowsCreateString(L"Windows.Foundation.Uri",22,&s);IActivationFactory*uri=nullptr;HRESULT hr=ro(s,__uuidof(IActivationFactory),(void**)&uri);logFactory(L"XAML_NATIVE",L"Windows.Foundation.Uri",hr,uri);pass&=SUCCEEDED(hr)&&uri;if(uri)uri->Release();WindowsDeleteString(s);
 WindowsCreateString(L"SystemSettings.ViewModel.SettingEntry",(UINT)wcslen(L"SystemSettings.ViewModel.SettingEntry"),&s);struct{ULONGLONG a;IInspectable*out;ULONGLONG z;}o={0x1122334455667788ULL,nullptr,0x8877665544332211ULL};hr=ra(s,&o.out);WCHAR owner[32768]=L"none";if(SUCCEEDED(hr)&&o.out){HMODULE m;if(GetModuleHandleExW(6,(PCWSTR)*(void**)o.out,&m))GetModuleFileNameW(m,owner,32768);}
 auto get=(HRESULT(WINAPI*)(HSTRING,IActivationFactory**))GetProcAddress(GetModuleHandleW(L"SystemSettingsViewModel.Desktop.dll"),"DllGetActivationFactory");IActivationFactory*refFactory=nullptr;IInspectable*refObject=nullptr;HRESULT want=get(s,&refFactory);if(SUCCEEDED(want)&&refFactory){want=refFactory->ActivateInstance(&refObject);refFactory->Release();}
 bool ok=hr==want&&o.a==0x1122334455667788ULL&&o.z==0x8877665544332211ULL&&((FAILED(hr)&&!o.out)||(SUCCEEDED(hr)&&o.out&&wcsstr(owner,L"\\Image\\4\\")));fwprintf(f,L"XAML_RA\t%08lx\t%08lx\t%u\t%ls\n",want,hr,ok,owner);fflush(f);pass&=ok;if(refObject)refObject->Release();if(o.out)o.out->Release();WindowsDeleteString(s);return pass;
}
'''
t=(H/'FactoryFixture.cpp').read_text();pos=t.index('int WINAPI wWinMain');t=t[:pos]+declaration+probe+t[pos:];t=t.replace('HMODULE list[1024];','if(!checkXaml())return 13;HMODULE list[1024];');(X/'Fixture.cpp').write_text(t)
z=X.parents[3]/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe';libs=['-lole32','-lapi-ms-win-core-winrt-l1-1-0','-lapi-ms-win-core-winrt-string-l1-1-0','-lshell32','-luser32','-lbcrypt','-lpsapi']
p=subprocess.run([str(z),'c++','-target','x86_64-windows-gnu','-O2','-std=c++17','-municode','-Wl,--subsystem,windows',str(X/'Fixture.cpp'),'-o',str(X/'Fixture.exe'),*libs],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=60);(X/'fixture-build.log').write_bytes(p.stdout+p.stderr)
if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
# Production guard remains exact canonical EXE; ONLY fixture guard gains new owned hash.
import re
p=X/'SelectorPins.h';t=p.read_text();t=re.sub(r'#define OWN_EXE_PATH .*', lambda _: '#define OWN_EXE_PATH L"'+str(X/'Fixture.exe').replace('\\','\\\\')+'"',t);t=re.sub(r'#define OWN_EXE_SHA ".*?"','#define OWN_EXE_SHA "'+hashlib.sha256((X/'Fixture.exe').read_bytes()).hexdigest()+'"',t);p.write_text(t)
