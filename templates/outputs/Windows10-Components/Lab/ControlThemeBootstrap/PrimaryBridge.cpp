#include <windows.h>
#include <stdio.h>
struct State {DWORD size,version,result,complete,tid,processBefore,processAfter,threadBefore,threadAfter,processSame,threadSame,v2Before,v2After,dpiBefore,dpiAfter,initializerResult;ULONGLONG processContextBefore,processContextAfter,threadContextBefore,threadContextAfter;};
extern "C" __declspec(dllexport) State ControlBootstrapState={sizeof(State),1};
struct Input {ULONGLONG helper,initialize;};
extern "C" __declspec(dllexport) DWORD WINAPI ControlBootstrapInitialize(void*argument){
 State&s=ControlBootstrapState;Input*i=(Input*)argument;s.tid=GetCurrentThreadId();HMODULE user=GetModuleHandleW(L"user32.dll");
 typedef HANDLE(WINAPI*Process)(HANDLE);typedef HANDLE(WINAPI*Thread)();typedef BOOL(WINAPI*Equal)(HANDLE,HANDLE);typedef int(WINAPI*Awareness)(HANDLE);
 Process process=(Process)GetProcAddress(user,"GetDpiAwarenessContextForProcess");Thread thread=(Thread)GetProcAddress(user,"GetThreadDpiAwarenessContext");Equal equal=(Equal)GetProcAddress(user,"AreDpiAwarenessContextsEqual");Awareness awareness=(Awareness)GetProcAddress(user,"GetAwarenessFromDpiAwarenessContext");
 if(!i||!process||!thread||!equal||!awareness){s.result=ERROR_NOT_SUPPORTED;s.complete=1;return s.result;}
 HANDLE p=process(GetCurrentProcess()),t=thread();s.processContextBefore=(ULONGLONG)p;s.threadContextBefore=(ULONGLONG)t;s.processBefore=awareness(p);s.threadBefore=awareness(t);s.v2Before=equal(t,(HANDLE)-4);s.dpiBefore=GetDpiForSystem();
 if((int)s.processBefore<0||(int)s.threadBefore<0){s.result=ERROR_INVALID_DATA;s.complete=1;return s.result;}
 auto initialize=(DWORD(WINAPI*)(void*))i->initialize;
 if(initialize!=(void*)GetProcAddress((HMODULE)i->helper,"ControlTheme10Initialize")){s.result=ERROR_ACCESS_DENIED;s.complete=1;return s.result;}
 s.initializerResult=initialize(nullptr);p=process(GetCurrentProcess());t=thread();s.processContextAfter=(ULONGLONG)p;s.threadContextAfter=(ULONGLONG)t;s.processAfter=awareness(p);s.threadAfter=awareness(t);s.v2After=equal(t,(HANDLE)-4);s.dpiAfter=GetDpiForSystem();
 s.processSame=equal((HANDLE)s.processContextBefore,p);s.threadSame=equal((HANDLE)s.threadContextBefore,t);
 s.result=s.initializerResult?s.initializerResult:(!s.processSame||!s.threadSame||s.dpiBefore!=s.dpiAfter?ERROR_REVISION_MISMATCH:0);s.complete=1;return s.result;
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD reason,void*){if(reason==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(h);return TRUE;}
