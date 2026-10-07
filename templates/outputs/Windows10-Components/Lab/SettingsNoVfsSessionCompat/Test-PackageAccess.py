"""Own AppContainer fixture using existing package SID, no package activation/profile."""
import ctypes as C,subprocess,uuid,shutil,json
from ctypes import wintypes as W
from pathlib import Path
from PackageAccess import grant_private_runtime
from Lifecycle import api,P,close,wait
LAB=Path(__file__).resolve().parent;directory=LAB/'fixtures'/uuid.uuid4().hex;directory.mkdir(parents=True)
family='windows.immersivecontrolpanel_cw5n1h2txyewy'
receipt=grant_private_runtime(directory,family)
# Create child tree AFTER grant, as the actual callback will do.
runtime=directory/'activation';runtime.mkdir();reader=runtime/'AccessFixture.exe';bridge=runtime/'ShellAppearanceBridge.dll';ini=runtime/'bootstrap.ini'
shutil.copyfile(LAB/'AccessFixture.exe',reader);ini.write_text('\n'.join([str(LAB.parent/'SettingsNoVfsCompat/SettingsFactorySelector.dll'),str(LAB.parents[1]/'Image/4/Windows/ImmersiveControlPanel/SystemSettings.dll'),str(LAB.parents[1]/'Image/4/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll'),str(LAB.parents[1]/'Image/4/Windows/ImmersiveControlPanel/Telemetry.Common.dll'),str(LAB.parent/'SettingsContentCompat/SettingsContentCompat.dll')]),encoding='utf-8')
u=C.WinDLL('userenv',use_last_error=True);derive=u.DeriveAppContainerSidFromAppContainerName;derive.restype=W.LONG;derive.argtypes=[W.LPCWSTR,C.POINTER(P)];sid=P()
if derive(family,C.byref(sid)):raise RuntimeError('SID derivation failed')
class CAPS(C.Structure):_fields_=[('sid',P),('capabilities',P),('count',W.DWORD),('reserved',W.DWORD)]
class SI(C.Structure):_fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('cbReserved',W.WORD),('bytes',P),('input',P),('output',P),('error',P)]
class SIX(C.Structure):_fields_=[('base',SI),('attrs',P)]
class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',W.DWORD),('tid',W.DWORD)]
initialize=api('InitializeProcThreadAttributeList',W.BOOL,[P,W.DWORD,W.DWORD,P]);update=api('UpdateProcThreadAttribute',W.BOOL,[P,W.DWORD,C.c_size_t,P,C.c_size_t,P,P]);delete=api('DeleteProcThreadAttributeList',None,[P]);size=C.c_size_t();initialize(None,1,0,C.byref(size));attributes=C.create_string_buffer(size.value)
if not initialize(attributes,1,0,C.byref(size)):raise C.WinError(C.get_last_error())
caps=CAPS(sid,None,0,0);pi=PI();si=SIX();si.base.cb=C.sizeof(si);si.attrs=C.addressof(attributes)
proof=dict(ActualPackageActivation=False,ActualSEH=False,ExistingPackageSIDOnly=True,NoRegistration=True,NoProfileCreated=True,ACL=receipt)
try:
 if not update(attributes,0,0x20009,C.byref(caps),C.sizeof(caps),None,None):raise C.WinError(C.get_last_error())
 command=C.create_unicode_buffer(subprocess.list2cmdline([str(reader),str(ini),str(bridge)]))
 create=api('CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,W.DWORD,P,W.LPCWSTR,P,P])
 if not create(str(reader),command,None,None,False,0x08080000,None,'C:/Windows/System32',C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
 if wait(pi.process,15000)!=0:raise RuntimeError('Own restricted reader timeout')
 code=W.DWORD();api('GetExitCodeProcess',W.BOOL,[P,P])(pi.process,C.byref(code))
 proof.update(Result=code.value,RealAppContainer=True,FiveDirectDllLoads=True,NtBackingIdentity=True,Passed=code.value==0)
finally:
 if pi.thread:close(pi.thread)
 if pi.process:close(pi.process)
 delete(attributes);a=C.WinDLL('advapi32');a.FreeSid.argtypes=[P];a.FreeSid(sid)
(LAB/'own-package-access-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2))
if not proof.get('Passed'):raise RuntimeError('Own AppContainer access proof failed')
