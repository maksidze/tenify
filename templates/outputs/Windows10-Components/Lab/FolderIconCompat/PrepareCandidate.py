"""Prepare a separate candidate; never edits frozen IconResourceMaximum."""
from pathlib import Path
import json,hashlib,shutil
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1];OUT=BASE/'Lab/IconRoutesNoVfsCompat';OUT.mkdir(exist_ok=True)
if (OUT/'IconRoutesNoVfs.c').exists():raise RuntimeError('Initial seed already exists. Use candidate Build-Test.py; do not overwrite reviewed source.')
seed=LAB/'ResourceRoutesNoVfs'
source=(seed/'IconRoutes.c').read_text().replace('../../SettingsContentCompat/HashCheck.h','../SettingsContentCompat/HashCheck.h')
# All transient init/publication errors fail closed. The caller must tear down
# the new owned process; live restoration is deliberately not a contract.
source=source.replace('static BOOL installed,restorePending;','static BOOL installed,restorePending,terminalFailure;')
source=source.replace('static HRSRC remember(HRSRC resource,HMODULE module){', 'static HRSRC legacyRememberUnused(HRSRC resource,HMODULE module){')
start=source.index('static HMODULE resourceModule(');end=source.index('static HICON WINAPI',start)
source=source[:start]+'''static HRSRC remember(HRSRC resource,HMODULE module){(void)module;return resource;}
static HMODULE resourceModule(HMODULE original,HRSRC resource){
 MEMORY_BASIC_INFORMATION info;
 if(resource&&VirtualQuery(resource,&info,sizeof(info)))for(int i=0;i<ROUTE_COUNT;i++)
  if(data[i]&&(void*)((ULONG_PTR)data[i]&~(ULONG_PTR)3)==info.AllocationBase)return data[i];
 return original;
}
'''+source[end:]
# Retain original page protection in the journal and never ignore a failed restore.
source=source.replace('void *before,*after;} PATCH;','void *before,*after;DWORD protection;} PATCH;')
source=source.replace('VirtualProtect(slot,sizeof(void*),old,&discard);if(prior==hooks[h].original)patches[patchCount++]=(PATCH){slot,prior,hooks[h].hook};break;',
'''BOOL restoredPage=VirtualProtect(slot,sizeof(void*),old,&discard);if(prior==hooks[h].original)patches[patchCount++]=(PATCH){slot,prior,hooks[h].hook,old};
if(!restoredPage||prior!=hooks[h].original){terminalFailure=TRUE;restorePending=TRUE;return FALSE;}break;''')
source=source.replace('VirtualProtect(p->slot,8,old,&ignored);','if(!VirtualProtect(p->slot,8,p->protection,&ignored))failures++;')
# Foreign slots must be detected before publishing "active=false" or reverting
# any other slot, and Initialize must never return false success on a retry.
source=source.replace('AcquireSRWLockExclusive(&patchLock);active=FALSE;DWORD failures=0,foreign=0;',
'''AcquireSRWLockExclusive(&patchLock);for(DWORD j=0;j<patchCount;j++)if(*patches[j].slot!=patches[j].before&&*patches[j].slot!=patches[j].after){ReleaseSRWLockExclusive(&patchLock);return ERROR_BUSY;}active=FALSE;DWORD failures=0,foreign=0;''')
source=source.replace('static DWORD initialize(BOOL fixture){if(installed)return restorePending?ERROR_BUSY:ERROR_SUCCESS;',
'''static DWORD initialize(BOOL fixture){if(terminalFailure)return ERROR_INVALID_STATE;if(installed){if(restorePending)return ERROR_BUSY;for(DWORD j=0;j<patchCount;j++)if(*patches[j].slot!=patches[j].after)return ERROR_BUSY;return ERROR_SUCCESS;}''')
old='if(_wcsicmp(exe,fixture?FIXTURE_PATH:EXPLORER_PATH)||!hashMatches(exe,fixture?FIXTURE_SHA:EXPLORER_SHA))return ERROR_ACCESS_DENIED;'
new='if(fixture?(!((!_wcsicmp(exe,FIXTURE_PATH)&&hashMatches(exe,FIXTURE_SHA))||(!_wcsicmp(exe,ROUTE_FIXTURE_PATH)&&hashMatches(exe,ROUTE_FIXTURE_SHA)))):(_wcsicmp(exe,EXPLORER_PATH)||!hashMatches(exe,EXPLORER_SHA)))return ERROR_ACCESS_DENIED;'
assert old in source;source=source.replace(old,new)
# A callback address must remain valid even if a caller unloads its DLL handle.
source=source.replace(' HOOK list[]={',' HMODULE pinned=NULL;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(PCWSTR)&initialize,&pinned))return GetLastError();\n HOOK list[]={')
source=source.replace('if(!patchModule(modules[i])){restoreLocked(NULL);return ERROR_WRITE_FAULT;}','if(!patchModule(modules[i])){terminalFailure=TRUE;restoreLocked(NULL);return ERROR_WRITE_FAULT;}')
source=source.replace('if(m&&!resource&&!(flags&LOAD_LIBRARY_AS_IMAGE_RESOURCE))patchModule(m);','if(m&&!resource&&!(flags&LOAD_LIBRARY_AS_IMAGE_RESOURCE)&&!patchModule(m))terminalFailure=TRUE;')
source=source.replace('if(m)patchModule(m);return m;','if(m&&!patchModule(m))terminalFailure=TRUE;return m;')
source+='''
__declspec(dllexport) DWORD WINAPI GetNoVfsIconFailures(void*unused){(void)unused;return terminalFailure||locationTerminal;}
__declspec(dllexport) DWORD WINAPI NoVfsIconsInitialize(void*unused){(void)unused;DWORD result=InitializeIconRoutes(NULL);if(result)return result;result=initializeFolderKey(FALSE);if(result){terminalFailure=TRUE;RestoreIconRoutes(NULL);}return result;}
__declspec(dllexport) DWORD WINAPI NoVfsIconsRestore(void*unused){DWORD result=RestoreFolderCacheKeyFixture(unused);return result?result:RestoreIconRoutes(unused);}
'''
(OUT/'IconRoutesNoVfs.c').write_text(source)
key=(seed/'CacheKey.h').read_text()
key=key.replace('static BOOL locationInstalled;', 'static BOOL locationInstalled,locationTerminal;')
key=key.replace('__declspec(dllexport) DWORD WINAPI InitializeFolderCacheKeyFixture(void*unused){\n (void)unused;WCHAR path[32768];if(!GetModuleFileNameW(NULL,path,32768)||_wcsicmp(path,FIXTURE_PATH)||!hashMatches(path,FIXTURE_SHA))return ERROR_ACCESS_DENIED;',
'''static DWORD initializeFolderKey(BOOL fixture){
 WCHAR path[32768];if(!GetModuleFileNameW(NULL,path,32768))return ERROR_ACCESS_DENIED;
 if(fixture?(_wcsicmp(path,FIXTURE_PATH)||!hashMatches(path,FIXTURE_SHA)):(_wcsicmp(path,EXPLORER_PATH)||!hashMatches(path,EXPLORER_SHA)))return ERROR_ACCESS_DENIED;''')
key=key.replace('AcquireSRWLockExclusive(&locationGate);DWORD result=0;','AcquireSRWLockExclusive(&locationGate);DWORD result=0;\n if(locationTerminal){result=ERROR_INVALID_STATE;goto end;}',1)
key=key.replace('if(!module){result=GetLastError();goto end;}','''if(!module){result=GetLastError();goto end;}
 WCHAR physical[32768],device[32768],expected[32768];
 if(!K32GetMappedFileNameW(GetCurrentProcess(),module,physical,32768)||!QueryDosDeviceW(L"C:",device,32768)){result=ERROR_REVISION_MISMATCH;goto end;}
 swprintf(expected,32768,L"%ls\\\\Windows\\\\System32\\\\windows.storage.dll",device);
 if(_wcsicmp(physical,expected)){result=ERROR_REVISION_MISMATCH;goto end;}''')
key=key.replace('if(!VirtualProtect(locationSlot,8,locationProtection,&ignore)||prior!=(void*)locationOriginal){result=ERROR_WRITE_FAULT;goto end;}','if(!VirtualProtect(locationSlot,8,locationProtection,&ignore)||prior!=(void*)locationOriginal){locationTerminal=TRUE;result=ERROR_WRITE_FAULT;goto end;}')
key=key.replace('__declspec(dllexport) DWORD WINAPI RestoreFolderCacheKeyFixture', '__declspec(dllexport) DWORD WINAPI InitializeFolderCacheKeyFixture(void*unused){(void)unused;return initializeFolderKey(TRUE);}\n__declspec(dllexport) DWORD WINAPI RestoreFolderCacheKeyFixture')
(OUT/'CacheKey.h').write_text(key)
shutil.copy2(seed/'CacheKeyPins.h',OUT/'CacheKeyPins.h')
# Routes are generated by the candidate build after both own fixtures are built.
(OUT/'seed-routes.json').write_bytes((seed/'fixture-manifest.json').read_bytes())
print(OUT)
