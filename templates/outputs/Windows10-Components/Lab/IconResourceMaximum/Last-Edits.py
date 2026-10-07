from pathlib import Path
p=Path(__file__).with_name('IconRoutes.c');s=p.read_text()
s=s.replace('static BOOL installed,active,restorePending;', 'static BOOL installed,restorePending;static volatile BOOL active;')
start=s.index('static int pathIndex(');end=s.index('static HMODULE routeModule',start)
s=s[:start]+'''static int pathIndex(PCWSTR path){WCHAR expanded[32768],full[32768];if(!path||!ExpandEnvironmentStringsW(path,expanded,32768))return -1;BOOL bare=!wcschr(expanded,L'\\\\')&&!wcschr(expanded,L'/')&&!wcschr(expanded,L':');if(bare){DWORD n=SearchPathW(NULL,expanded,NULL,32768,full,NULL);if(!n||n>=32768)return -1;}else{DWORD n=GetFullPathNameW(expanded,32768,full,NULL);if(!n||n>=32768)return -1;}for(int i=0;i<ROUTE_COUNT;i++)if(!_wcsicmp(full,routes[i].host))return i;return -1;}
''' +s[end:]
s=s.replace('if(!module)return module;', 'if(!active||!module)return module;')
s=s.replace('static PCWSTR routePath(PCWSTR path){int i=', 'static PCWSTR routePath(PCWSTR path){if(!active)return path;int i=')
s=s.replace('FARPROC p=GetProcAddress(module,name);if((ULONG_PTR)', 'FARPROC p=GetProcAddress(module,name);if(!active)return p;if((ULONG_PTR)')
old='static BOOL patchModule(HMODULE module){AcquireSRWLockExclusive(&patchLock);BOOL ok=!active||patchModuleLocked(module);ReleaseSRWLockExclusive(&patchLock);return ok;}'
new='''static BOOL patchModule(HMODULE module){AcquireSRWLockExclusive(&patchLock);BOOL ok=TRUE;HMODULE temporary=NULL;if(active&&GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(PCWSTR)module,&temporary)){if(temporary==module)ok=patchModuleLocked(module);else ok=FALSE;}ReleaseSRWLockExclusive(&patchLock);if(temporary)FreeLibrary(temporary);return ok;}'''
assert old in s;s=s.replace(old,new)
p.write_text(s,encoding='utf-8')
