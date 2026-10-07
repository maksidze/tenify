"""Generate private Start session sources from the proven bounded adapters.

No package activation, registry changes, compilation, or process control.
The bounded production sources are read only.
"""
from pathlib import Path
import hashlib, json, re
LAB=Path(__file__).resolve().parent
BASE=LAB.parent.parent
S=BASE/'Lab/SettingsSessionCompat'
START=BASE/'Lab/StartCompat'

def replace(s,a,b,n=1):
    assert s.count(a)==n,(a[:100],s.count(a),n)
    return s.replace(a,b)

original=(START/'StartCompatHostProbe.c').read_text(encoding='utf-8-sig')
backend=original
backend=re.sub(r'\(\(ULARGE_INTEGER\*\)&(\w+)\)->QuadPart',r'sessionFileTimeValue(&\1)',backend)
backend=replace(backend,'static FILE *logFile;',r'''
static ULONGLONG sessionFileTimeValue(const FILETIME*f){return ((ULONGLONG)f->dwHighDateTime<<32)|f->dwLowDateTime;}
static wchar_t sessionCancel[32768];
static HANDLE sessionOwner;
static BOOL sessionUntilStop;
static BOOL sessionCancelled(void){return (sessionCancel[0]&&GetFileAttributesW(sessionCancel)!=INVALID_FILE_ATTRIBUTES)||(sessionOwner&&WaitForSingleObject(sessionOwner,0)!=WAIT_TIMEOUT);}
static FILE *logFile;''')
backend=replace(backend,'if(argc>2&&!wcscmp(argv[1],L"-p")){',r'''BOOL expandedInternal=argc==12&&expectedPackage[0]&&!wcscmp(argv[7],L"--attach");BOOL brokerAttach=FALSE;if(!expandedInternal)for(int i=1;i+1<argc;i++)if(!wcscmp(argv[i],L"-p"))brokerAttach=TRUE;
 if(brokerAttach){''')
needle='wcscpy(slash+1,L"BrokerStartCompat.ini");'
backend=replace(backend,needle,needle+r'''
  for(int i=1;i+1<argc;i++)if(!wcscmp(argv[i],L"--config")){if(wcschr(argv[i+1],L':'))wcsncpy(config,argv[i+1],32767);else wcscpy(slash+1,argv[i+1]);}
  GetPrivateProfileStringW(L"Debugger",L"CancelFile",L"",sessionCancel,32768,config);
  sessionUntilStop=GetPrivateProfileIntW(L"Debugger",L"UntilStop",0,config)!=0;
  wchar_t ownerBirthText[32],ownerPath[32768],actualOwnerPath[32768];GetPrivateProfileStringW(L"Debugger",L"OwnerBirth",L"",ownerBirthText,32,config);GetPrivateProfileStringW(L"Debugger",L"OwnerPath",L"",ownerPath,32768,config);
  DWORD ownerPid=GetPrivateProfileIntW(L"Debugger",L"OwnerPid",0,config),ownerSize=32768;FILETIME ob,oe,ok,ou;
  sessionOwner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,ownerPid);
  if(!sessionOwner||!GetProcessTimes(sessionOwner,&ob,&oe,&ok,&ou)||sessionFileTimeValue(&ob)!=wcstoull(ownerBirthText,NULL,10)||!QueryFullProcessImageNameW(sessionOwner,0,actualOwnerPath,&ownerSize)||_wcsicmp(actualOwnerPath,ownerPath)){if(sessionOwner)CloseHandle(sessionOwner);sessionOwner=NULL;return 71;}
''')
backend=replace(backend,'if(!stopping && GetTickCount64()>deadline){', 'if(!stopping && (sessionCancelled()||GetTickCount64()>deadline)){')
needle='logline("DETACH afterBootstrap success=%d remoteDebugger=%d trace=%p",detached,stillDebugged,remoteTrace);'
backend=replace(backend,needle,needle+'if(detached&&!stillDebugged&&sessionUntilStop){deadline=~0ULL;logline("SESSION UntilStop after bounded bootstrap; exact owner handle + durable cancel");}')
backend=replace(backend,'CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseDesktop(desk);logline("COMPLETE', 'CloseHandle(pi.hThread);CloseHandle(pi.hProcess);if(sessionOwner){CloseHandle(sessionOwner);sessionOwner=NULL;}CloseDesktop(desk);logline("COMPLETE')
(LAB/'StartSessionBackend.c').write_text(backend,encoding='utf-8')
(LAB/'StartCompatTrace.h').write_bytes((START/'StartCompatTrace.h').read_bytes())

entry=(S/'SettingsSessionEntry.c').read_text(encoding='utf-8-sig')
entry=replace(entry,'L"VfsProxy",L"VfsInstance",L"DeadlineTick"','L"OwnerPid",L"OwnerBirth",L"OwnerPath",L"DeadlineTick",L"UntilStop",L"ServerArgument"')
entry=replace(entry,'static WCHAR v[8][32768];for(int a=0;a<8;a++)','static WCHAR v[11][32768];for(int a=0;a<11;a++)')
entry=replace(entry,'for(int a=0;a<8;a++){','for(int a=0;a<11;a++){')
entry=replace(entry,'ULONGLONG deadline=wcstoull(v[7],NULL,10),now=GetTickCount64();BOOL cancelled=present(v[3])||!deadline||now>=deadline;',r'''ULONGLONG deadline=wcstoull(v[8],NULL,10),now=GetTickCount64();BOOL untilStop=wcstoul(v[9],NULL,10)!=0;
 HANDLE owner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,wcstoul(v[5],NULL,10));FILETIME ob,oe,ok,ou;WCHAR ownerPath[32768];DWORD ownerLength=32768;
 BOOL ownerValid=owner&&WaitForSingleObject(owner,0)==WAIT_TIMEOUT&&GetProcessTimes(owner,&ob,&oe,&ok,&ou)&&filetimeValue(&ob)==wcstoull(v[6],NULL,10)&&QueryFullProcessImageNameW(owner,0,ownerPath,&ownerLength)&&!_wcsicmp(ownerPath,v[7]);
 if(owner)CloseHandle(owner);
 BOOL cancelled=present(v[3])||!ownerValid||(!untilStop&&(!deadline||now>=deadline));''')
entry=replace(entry,'DWORD seconds=(DWORD)((deadline-now+999)/1000);if(seconds>3600)seconds=3600;', 'DWORD seconds=untilStop?30:(DWORD)((deadline-now+999)/1000);if(seconds>3600)seconds=3600;')
entry=replace(entry,'if(present(v[3])||GetTickCount64()>=deadline){','if(present(v[3])||(!untilStop&&GetTickCount64()>=deadline)){')
old='swprintf(text,32768,L"[Debugger]\\r\\nReport=%ls\\r\\nTarget=%ls\\r\\nSeconds=%lu\\r\\nServerArgument=\\r\\nProxy=%ls\\r\\nPackageFullName=%ls\\r\\nDeadlineFileTime=%llu\\r\\nVfsProxy=%ls\\r\\nVfsInstance=%ls\\r\\nCancelFile=%ls\\r\\n",report,v[0],seconds,v[4],v[1],expiry,v[5],v[6],v[3]);'
new='swprintf(text,32768,L"[Debugger]\\r\\nReport=%ls\\r\\nTarget=%ls\\r\\nSeconds=%lu\\r\\nServerArgument=%ls\\r\\nProxy=%ls\\r\\nPackageFullName=%ls\\r\\nDeadlineFileTime=%llu\\r\\nCancelFile=%ls\\r\\nDetachAfterBootstrap=1\\r\\nUntilStop=%u\\r\\nOwnerPid=%ls\\r\\nOwnerBirth=%ls\\r\\nOwnerPath=%ls\\r\\n",report,v[0],seconds,v[10],v[4],v[1],expiry,v[3],untilStop,v[5],v[6],v[7]);'
entry=replace(entry,old,new)
(LAB/'StartSessionEntry.c').write_text(entry,encoding='utf-8')

control=(S/'SessionControl.c').read_text(encoding='utf-8-sig')
(LAB/'SessionControl.c').write_text(control,encoding='utf-8')
(LAB/'FixtureChild.c').write_bytes((S/'FixtureChild.c').read_bytes())
(LAB/'FixtureBackend.c').write_bytes((S/'FixtureBackend.c').read_bytes())

# Reuse audited process identity, owned registry rollback, atomic claim parsing,
# and suspended Job-assigned package control. Later code supplies session policy.
core=(S/'SessionController.py').read_text(encoding='utf-8-sig').split('\ndef preflight(state):',1)[0]
core=core.replace('SettingsSessionRestore_','StartSessionRestore_').replace('Settings10ManualLauncher','StartMenu10Session')
core=core.replace('"""Opt-in bounded Settings package debugger. No package activation is performed here."""','"""Private shared mechanisms for Start session; generated from the audited Settings controller."""')
(LAB/'SessionCore.py').write_text(core,encoding='utf-8')
sources=[START/'StartCompatHostProbe.c',START/'StartCompatTrace.h',S/'SettingsSessionEntry.c',S/'SessionController.py',S/'SessionControl.c',S/'FixtureChild.c',S/'FixtureBackend.c']
(LAB/'source-provenance.json').write_text(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},indent=2),encoding='utf-8')
print('Private Start session sources prepared; production files unchanged; no process or package action.')
