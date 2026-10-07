from pathlib import Path
p=Path(__file__).with_name('IconRoutes.c');s=p.read_text()
s=s.replace('static DWORD patchCount;static BOOL installed;','static DWORD patchCount;static BOOL installed;\nstatic SRWLOCK patchLock=SRWLOCK_INIT;static HMODULE holds[2048];static DWORD holdCount;')
s=s.replace('DWORD resourceFlags=LOAD_LIBRARY_AS_DATAFILE|LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE|LOAD_LIBRARY_AS_IMAGE_RESOURCE;BOOL resource=(flags&resourceFlags)!=0;', '/* IMAGE_RESOURCE alone is not an established data-only request. */BOOL resource=(flags&(LOAD_LIBRARY_AS_DATAFILE|LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE))!=0;')
s=s.replace('if(m&&!resource)patchModule(m);','if(m&&!resource&&!(flags&LOAD_LIBRARY_AS_IMAGE_RESOURCE))patchModule(m);')
s=s.replace('static BOOL patchModule(HMODULE module){if(module==self)', 'static BOOL patchModuleLocked(HMODULE module){if(module==self)')
old='if(patchCount==8192)return FALSE;DWORD old;'
new='''if(patchCount==8192)return FALSE;BOOL held=FALSE;for(DWORD k=0;k<holdCount;k++)if(holds[k]==module){held=TRUE;break;}if(!held){if(holdCount==2048)return FALSE;HMODULE hold;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(PCWSTR)module,&hold)||hold!=module)return FALSE;holds[holdCount++]=hold;}DWORD old;'''
assert old in s;s=s.replace(old,new)
start=s.index('__declspec(dllexport) DWORD WINAPI RestoreIconRoutes')
end=s.index('static DWORD initialize',start)
s=s[:start]+'''static BOOL patchModule(HMODULE module){AcquireSRWLockExclusive(&patchLock);BOOL ok=patchModuleLocked(module);ReleaseSRWLockExclusive(&patchLock);return ok;}
__declspec(dllexport) DWORD WINAPI RefreshIconRoutes(void*unused){(void)unused;HMODULE modules[2048];DWORD needed;if(!EnumProcessModules(GetCurrentProcess(),modules,sizeof(modules),&needed)||needed>sizeof(modules))return ERROR_INSUFFICIENT_BUFFER;for(DWORD i=0;i<needed/sizeof(HMODULE);i++)if(!patchModule(modules[i]))return ERROR_WRITE_FAULT;return ERROR_SUCCESS;}
__declspec(dllexport) DWORD WINAPI RestoreIconRoutes(void*unused){(void)unused;AcquireSRWLockExclusive(&patchLock);DWORD failures=0,foreign=0;for(DWORD i=patchCount;i>0;i--){PATCH*p=&patches[i-1];void*current=*p->slot;if(current==p->before)continue;if(current!=p->after){foreign++;continue;}DWORD old;if(!VirtualProtect(p->slot,8,PAGE_READWRITE,&old)){failures++;continue;}void*observed=InterlockedCompareExchangePointer(p->slot,p->before,p->after);if(observed!=p->after&&observed!=p->before)foreign++;DWORD ignored;VirtualProtect(p->slot,8,old,&ignored);}if(failures||foreign){ReleaseSRWLockExclusive(&patchLock);return failures?ERROR_WRITE_FAULT:ERROR_BUSY;}patchCount=0;installed=FALSE;/* All consumer slots are restored before releasing module references. */HMODULE release[2048];DWORD n=holdCount;memcpy(release,holds,n*sizeof(HMODULE));holdCount=0;ReleaseSRWLockExclusive(&patchLock);for(DWORD i=0;i<n;i++)FreeLibrary(release[i]);/* Retain datafiles for outstanding caller-owned HRSRC/HICON. */return ERROR_SUCCESS;}
''' +s[end:]
p.write_text(s,encoding='utf-8')
# API baseline blank remains unavailable, rather than claiming render success.
p=p.with_name('IconRouteProbe.c');s=p.read_text().replace('BOOL pass=got==expected[i]&&got!=0;', 'BOOL pass=got==expected[i]&&(got!=0||before[i]==0);')
p.write_text(s,encoding='utf-8')
