#define _WIN32_WINNT 0x0A00
#define NTDDI_VERSION 0x0A000000
#define PSAPI_VERSION 1
#include <windows.h>
#include <processsnapshot.h>
#include <dbghelp.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>

// Reads only a PSS clone. No original thread is opened, suspended, or modified.
static HANDLE clone;
static ULONGLONG deadline;
static int timedOut;
static ULONGLONG ft64(FILETIME f) { return ((ULONGLONG)f.dwHighDateTime<<32)|f.dwLowDateTime; }
static int expired(void) { if (GetTickCount64()>deadline) timedOut=1; return timedOut; }
static void js(const char *s) { putchar('"'); for(;*s;s++){ unsigned char c=*s; if(c=='"'||c=='\\') putchar('\\'); if(c>=32) putchar(c); else printf("\\u%04x",c); } putchar('"'); }
static void jw(const wchar_t *w) { char u[16384]; int n=WideCharToMultiByte(CP_UTF8,0,w,-1,u,sizeof u,0,0); js(n?u:""); }
static void error(const char *stage,DWORD e) { printf("{\"event\":\"error\",\"stage\":"); js(stage); printf(",\"code\":%lu}\n",e); }
static BOOL CALLBACK readClone(HANDLE p,DWORD64 a,PVOID b,DWORD n,LPDWORD done) {
    SIZE_T got=0; if(expired()) { *done=0; return FALSE; }
    BOOL ok=ReadProcessMemory(p,(LPCVOID)(uintptr_t)a,b,n,&got); *done=(DWORD)got; return ok;
}
static int physicalPath(HANDLE p,HMODULE m,wchar_t *out,DWORD cap) {
    wchar_t nt[4096],drives[512],dev[4096];
    if(!GetMappedFileNameW(p,m,nt,4096)) return 0;
    DWORD n=GetLogicalDriveStringsW(512,drives); if(!n||n>=512) return 0;
    for(wchar_t *d=drives;*d;d+=wcslen(d)+1) {
        wchar_t key[3]={d[0],L':',0};
        if(QueryDosDeviceW(key,dev,4096)) { size_t z=wcslen(dev);
            if(!_wcsnicmp(nt,dev,z) && nt[z]==L'\\') { if(wcslen(nt+z)+3>=cap) return 0; swprintf(out,cap,L"%ls%ls",key,nt+z); return 1; }
        }
    }
    return 0;
}
static int imageInfo(HANDLE p,HMODULE m,DWORD *sz,DWORD *stamp) {
    IMAGE_DOS_HEADER dos; IMAGE_NT_HEADERS64 nt; SIZE_T n;
    if(!ReadProcessMemory(p,m,&dos,sizeof dos,&n)||n!=sizeof dos||dos.e_magic!=IMAGE_DOS_SIGNATURE||dos.e_lfanew<0||dos.e_lfanew>0x100000) return 0;
    if(!ReadProcessMemory(p,(char*)m+dos.e_lfanew,&nt,sizeof nt,&n)||n!=sizeof nt||nt.Signature!=IMAGE_NT_SIGNATURE||nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;
    *sz=nt.OptionalHeader.SizeOfImage; *stamp=nt.FileHeader.TimeDateStamp; return 1;
}
static int diskMatches(const wchar_t *path,DWORD sz,DWORD stamp) {
    HANDLE f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,0,OPEN_EXISTING,0,0); if(f==INVALID_HANDLE_VALUE) return 0;
    IMAGE_DOS_HEADER dos; IMAGE_NT_HEADERS64 nt; DWORD n; int ok=0;
    if(ReadFile(f,&dos,sizeof dos,&n,0)&&n==sizeof dos&&dos.e_magic==IMAGE_DOS_SIGNATURE&&dos.e_lfanew>=0&&dos.e_lfanew<=0x100000) {
        SetFilePointer(f,dos.e_lfanew,0,FILE_BEGIN);
        if(ReadFile(f,&nt,sizeof nt,&n,0)&&n==sizeof nt&&nt.Signature==IMAGE_NT_SIGNATURE&&nt.OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            ok=nt.OptionalHeader.SizeOfImage==sz&&nt.FileHeader.TimeDateStamp==stamp;
    } CloseHandle(f); return ok;
}
static int loadModules(void) {
    HMODULE mods[2048]; DWORD needed;
    if(!EnumProcessModulesEx(clone,mods,sizeof mods,&needed,LIST_MODULES_64BIT)) {error("EnumProcessModulesEx",GetLastError());return 0;}
    if(needed>sizeof mods) {error("moduleLimit",ERROR_MORE_DATA);return 0;}
    for(DWORD i=0;i<needed/sizeof(HMODULE);i++) {
        if(expired()) return 0;
        DWORD sz=0,stamp=0; wchar_t path[4096]=L"";
        int valid=imageInfo(clone,mods[i],&sz,&stamp)&&physicalPath(clone,mods[i],path,4096)&&diskMatches(path,sz,stamp);
        SetLastError(0); DWORD64 loaded=valid?SymLoadModuleExW(clone,0,path,0,(DWORD64)(uintptr_t)mods[i],sz,0,0):0; DWORD err=GetLastError();
        printf("{\"event\":\"module\",\"base\":\"0x%llx\",\"size\":%lu,\"timestamp\":%lu,\"physicalPath\":",(unsigned long long)(uintptr_t)mods[i],sz,stamp); jw(path);
        printf(",\"diskHeaderMatches\":%s,\"symbolsLoaded\":%s,\"symbolError\":%lu}\n",valid?"true":"false",loaded?"true":"false",err);
    } return 1;
}
static void frame(DWORD tid,int ix,DWORD64 pc,DWORD64 sp) {
    BYTE buf[sizeof(SYMBOL_INFO)+1024]; ZeroMemory(buf,sizeof buf); PSYMBOL_INFO sym=(PSYMBOL_INFO)buf; sym->SizeOfStruct=sizeof *sym; sym->MaxNameLen=1023;
    DWORD64 disp=0,base=SymGetModuleBase64(clone,pc); BOOL found=SymFromAddr(clone,pc,&disp,sym);
    printf("{\"event\":\"frame\",\"tid\":%lu,\"index\":%d,\"pc\":\"0x%llx\",\"sp\":\"0x%llx\",\"moduleBase\":\"0x%llx\",\"rva\":\"0x%llx\",\"symbol\":",tid,ix,pc,sp,base,base?pc-base:0);js(found?sym->Name:"");printf(",\"displacement\":%llu}\n",found?disp:0);
}
static int selected(DWORD tid,const wchar_t *list) {
    if(!wcscmp(list,L"all")) return 1;
    for(const wchar_t *s=list;*s;) { wchar_t *end; unsigned long n=wcstoul(s,&end,10); if(end==s) return 0; if(n==tid) return 1; if(*end!=L',') break; s=end+1; } return 0;
}
static int capture(DWORD pid,ULONGLONG birth,const wchar_t *path,const wchar_t *tids) {
    HANDLE target=0; HPSS snap=0; HPSSWALK walk=0; int sym=0,rc=1,count=0; DWORD e,code=0;
    FILETIME ct,et,kt,ut; wchar_t actual[4096]; DWORD cap=4096; PSS_PROCESS_INFORMATION pi; PSS_VA_CLONE_INFORMATION ci;
    deadline=GetTickCount64()+12000;
    // QUERY_INFORMATION, VM_READ, CREATE_PROCESS are required for clone/read/query.
    // DUP_HANDLE is needed by the snapshot API for the clone handle.
    target=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_CREATE_PROCESS|PROCESS_DUP_HANDLE, FALSE,pid);
    if(!target){error("OpenProcess",GetLastError());goto done;}
    if(!QueryFullProcessImageNameW(target,0,actual,&cap)||!GetProcessTimes(target,&ct,&et,&kt,&ut)||!GetExitCodeProcess(target,&code)){error("identityQuery",GetLastError());goto done;}
    if(GetProcessId(target)!=pid||ft64(ct)!=birth||_wcsicmp(path,actual)||code!=STILL_ACTIVE){error("identityMismatch",ERROR_INVALID_DATA);goto done;}
    printf("{\"event\":\"identityVerified\",\"pid\":%lu,\"birth\":\"%llu\",\"path\":",pid,birth);jw(actual);puts("}");
    e=PssCaptureSnapshot(target,PSS_CAPTURE_VA_CLONE|PSS_CAPTURE_THREADS|PSS_CAPTURE_THREAD_CONTEXT,CONTEXT_FULL,&snap);
    if(e){error("PssCaptureSnapshot",e);goto done;}
    e=PssQuerySnapshot(snap,PSS_QUERY_PROCESS_INFORMATION,&pi,sizeof pi); if(e){error("PssQueryProcess",e);goto done;}
    if(pi.ProcessId!=pid||ft64(pi.CreateTime)!=birth){error("snapshotIdentityMismatch",ERROR_INVALID_DATA);goto done;}
    e=PssQuerySnapshot(snap,PSS_QUERY_VA_CLONE_INFORMATION,&ci,sizeof ci);if(e){error("PssQueryClone",e);goto done;}clone=ci.VaCloneHandle;
    printf("{\"event\":\"snapshot\",\"pid\":%lu,\"clonePid\":%lu,\"originalFrozenFlag\":%s}\n",pid,GetProcessId(clone),(pi.Flags&PSS_PROCESS_FLAGS_FROZEN)?"true":"false");
    SymSetOptions(SYMOPT_DEFERRED_LOADS|SYMOPT_FAIL_CRITICAL_ERRORS|SYMOPT_NO_PROMPTS|SYMOPT_IGNORE_NT_SYMPATH|SYMOPT_UNDNAME);
    // Explicit local-only path; no symbol server, environment path or network lookup.
    if(!SymInitializeW(clone,L"C:\\__PssStackSymbols_None__",FALSE)){error("SymInitialize",GetLastError());goto done;} sym=1;
    if(!loadModules())goto done;
    e=PssWalkMarkerCreate(0,&walk);if(e){error("PssWalkMarkerCreate",e);goto done;}
    for(;;){
        PSS_THREAD_ENTRY t; e=PssWalkSnapshot(snap,PSS_WALK_THREADS,walk,&t,sizeof t);if(e==ERROR_NO_MORE_ITEMS)break;if(e){error("PssWalkThreads",e);goto done;}
        if(expired()){error("deadline",WAIT_TIMEOUT);goto done;}
        if(!selected(t.ThreadId,tids))continue;
        printf("{\"event\":\"thread\",\"tid\":%lu,\"pid\":%lu,\"birth\":\"%llu\",\"suspendCountAtCapture\":%u,\"contextSize\":%u,\"start\":\"0x%llx\"}\n",t.ThreadId,t.ProcessId,ft64(t.CreateTime),t.SuspendCount,t.SizeOfContextRecord,(unsigned long long)(uintptr_t)t.Win32StartAddress);
        if(t.ProcessId!=pid||!t.ContextRecord||t.SizeOfContextRecord<sizeof(CONTEXT)){error("threadContext",ERROR_INVALID_DATA);continue;}
        CONTEXT c=*t.ContextRecord; STACKFRAME64 s;ZeroMemory(&s,sizeof s); s.AddrPC.Offset=c.Rip;s.AddrPC.Mode=AddrModeFlat;s.AddrFrame.Offset=c.Rbp;s.AddrFrame.Mode=AddrModeFlat;s.AddrStack.Offset=c.Rsp;s.AddrStack.Mode=AddrModeFlat;
        DWORD64 lastPc=s.AddrPC.Offset,lastSp=s.AddrStack.Offset; int emitted=1, repeated=0;
        frame(t.ThreadId,0,s.AddrPC.Offset,s.AddrStack.Offset);
        for(int i=0;i<96&&!expired();i++){
            if(!StackWalk64(IMAGE_FILE_MACHINE_AMD64,clone,(HANDLE)(uintptr_t)t.ThreadId,&s,&c,readClone,SymFunctionTableAccess64,SymGetModuleBase64,0))break;
            if(!s.AddrPC.Offset)break;
            // The first StackWalk call may return the initial frame again.
            if(s.AddrPC.Offset==lastPc&&s.AddrStack.Offset==lastSp){if(++repeated>1)break;continue;}
            repeated=0;frame(t.ThreadId,emitted++,s.AddrPC.Offset,s.AddrStack.Offset);lastPc=s.AddrPC.Offset;lastSp=s.AddrStack.Offset;
        }count++;
    }
    if(timedOut){error("deadline",WAIT_TIMEOUT);goto done;}if(!count){error("noSelectedThreads",ERROR_NOT_FOUND);goto done;}rc=0;
done:
    if(walk)PssWalkMarkerFree(walk);
    if(sym)SymCleanup(clone);
    if(snap){e=PssFreeSnapshot(GetCurrentProcess(),snap);printf("{\"event\":\"snapshotFreed\",\"code\":%lu}\n",e);if(e)rc=1;}
    // VaCloneHandle belongs to the snapshot: PssFreeSnapshot closes it.
    if(target)CloseHandle(target);
    printf("{\"event\":\"complete\",\"ok\":%s,\"threads\":%d,\"originalThreadOperations\":0}\n",rc?"false":"true",count);return rc;
}

static HANDLE fixtureEvent;
__declspec(dllexport) __declspec(noinline) DWORD FixtureLevel3(void) { DWORD r=WaitForSingleObject(fixtureEvent,60000);return r+3; }
__declspec(dllexport) __declspec(noinline) DWORD FixtureLevel2(void) { volatile DWORD r=FixtureLevel3();return r+2; }
__declspec(dllexport) __declspec(noinline) DWORD FixtureLevel1(void) { volatile DWORD r=FixtureLevel2();return r+1; }
static DWORD WINAPI fixtureWorker(void *p) { (void)p;return FixtureLevel1(); }
static int fixture(void) {
    DWORD tid; FILETIME ct,et,kt,ut;fixtureEvent=CreateEventW(0,TRUE,FALSE,0);if(!fixtureEvent)return 1;
    HANDLE thread=CreateThread(0,0,fixtureWorker,0,0,&tid);if(!thread){CloseHandle(fixtureEvent);return 2;}
    GetProcessTimes(GetCurrentProcess(),&ct,&et,&kt,&ut);
    printf("{\"event\":\"ready\",\"pid\":%lu,\"tid\":%lu,\"birth\":\"%llu\",\"debugger\":%s}\n",GetCurrentProcessId(),tid,ft64(ct),IsDebuggerPresent()?"true":"false");
    for(int i=0;i<600;i++){Sleep(100);printf("{\"event\":\"heartbeat\",\"number\":%d}\n",i);}
    SetEvent(fixtureEvent);WaitForSingleObject(thread,2000);CloseHandle(thread);CloseHandle(fixtureEvent);return 0;
}
int wmain(int argc,wchar_t **argv){setvbuf(stdout,0,_IONBF,0);if(argc==2&&!wcscmp(argv[1],L"--fixture"))return fixture();if(argc!=5){fwprintf(stderr,L"usage: PssStacks PID birthFILETIME exactPath tidsCSV|all\n");return 64;}return capture(wcstoul(argv[1],0,10),_wcstoui64(argv[2],0,10),argv[3],argv[4]);}
