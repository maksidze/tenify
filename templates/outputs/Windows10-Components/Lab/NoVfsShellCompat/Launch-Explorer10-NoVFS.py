"""Experimental own-child shell launcher; no global hooks or system-file writes."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import argparse, os, time, json, uuid, subprocess, sys, hashlib, struct, importlib.util

p=argparse.ArgumentParser()
p.add_argument('--run-directory',required=True)
p.add_argument('--preflight',action='store_true')
p.add_argument('--capture-debug',action='store_true')
p.add_argument('--xaml-quirk',action='store_true')
p.add_argument('--theme10',action='store_true')
p.add_argument('--control-theme10',action='store_true')
p.add_argument('--hybrid-theme10',action='store_true')
p.add_argument('--icons10',action='store_true')
p.add_argument('--no-legacy-touchpad',action='store_true')
p.add_argument('--profile',choices=['legacy','legacy-resource','legacy-watchers','host-dcomp','host-dcomp-resource'],default='legacy')
a=p.parse_args()
if a.theme10:
    p.error('--theme10 is disabled: full old theme breaks folder navigation. Use the scoped --control-theme10 candidate only after its preflight.')
if a.control_theme10 and a.hybrid_theme10:
    p.error('Choose one theme adapter, not both')
if (a.control_theme10 or a.hybrid_theme10) and a.profile!='host-dcomp-resource':
    p.error('--control-theme10 requires host-dcomp-resource')
base=Path(__file__).resolve().parents[2]
run=Path(a.run_directory).resolve();run.mkdir(parents=True,exist_ok=True)
image=base/'Image/4/Windows';compat=base/'Lab/WindowGroupCompat'
exe=base/'Runtime/Explorer10/explorer.exe'
win=Path(os.environ['WINDIR'])
state={'transport':'direct-private-modules','VFS':False,'experimental':True,'preflight':a.preflight,'profile':a.profile,'captureDebug':a.capture_debug,'xamlQuirk':a.xaml_quirk,'theme10':a.theme10,'controlTheme10':a.control_theme10,'hybridTheme10':a.hybrid_theme10,'noLegacyTouchpad':a.no_legacy_touchpad,'icons10':a.icons10,'status':'initializing','mappings':[],
       'systemFilesModified':False,'registeredPackagesChanged':False}
pin=Path(os.environ['APPDATA'])/'Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar/File Explorer.lnk'
state['taskbarPinSHA256']=hashlib.sha256(pin.read_bytes()).hexdigest() if pin.is_file() else None
statusSpec=importlib.util.spec_from_file_location('direct_atomic_status',base/'Lab/DirectLaunchLifecycle/AtomicStatus.py');statusModule=importlib.util.module_from_spec(statusSpec);statusSpec.loader.exec_module(statusModule)
def report():
    statusModule.write_json(run/'status.json',state)
def api(lib,name,result,types):
    f=getattr(lib,name);f.restype=result;f.argtypes=types;return f
P=C.c_void_p;D=W.DWORD
class SI(C.Structure):
    _fields_=[('cb',D),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',D),('y',D),('xs',D),('ys',D),('xc',D),('yc',D),('fill',D),('flags',D),('show',W.WORD),('res2',W.WORD),('pres2',P),('hin',P),('hout',P),('herr',P)]
class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',D),('tid',D)]
pi=PI();params=None;connected=False;desk=None;dll_dir=None;success=False;debugger=None;childJob=None
try:
    iconResources=[]
    if a.icons10:
        if a.profile!='host-dcomp-resource':raise RuntimeError('Icons10 currently tested only with host-dcomp-resource')
        import importlib.util
        iconLab=base/'Lab/IconResourceMaximum';iconManifest=iconLab/'manifest.json'
        iconSpec=importlib.util.spec_from_file_location('icon_maximum_mappings',iconLab/'IconMappings.py');iconModule=importlib.util.module_from_spec(iconSpec);iconSpec.loader.exec_module(iconModule)
        mappings=iconModule.get_icon_mappings()
        inventory=json.loads(iconManifest.read_text(encoding='utf-8-sig'))
        byPrivate={str(Path(row['Private']).resolve()).casefold():row for row in inventory['Records']}
        for mapping in mappings:
            if mapping['Kind']!='File':raise RuntimeError('Unsupported icon mapping kind')
            merged=Path(mapping['Source']);native=Path(mapping['Destination'])
            if native.suffix.lower()!='.mun':raise RuntimeError('Executable icon overlay forbidden')
            record=byPrivate[str(merged.resolve()).casefold()]
            iconResources.append((merged,native,{'sha256':record['PrivateSHA256'],'hostSHA256':record['HostSHA256']}))
        state['icons10Validation']={'manifestSHA256':iconModule.EXPECTED_MANIFEST_SHA256,'nativeResourceHashesMatched':True,'mergedResourceHashesMatched':True,'stockOnly':False,'munMappings':len(mappings),'resourceFiles':len(inventory['Records']),'resourceGroups':sum(len(r['ResourceGroups']) for r in inventory['Records'])}
    if a.no_legacy_touchpad and a.profile!='legacy-watchers':
        raise RuntimeError('Legacy touchpad capability opt-out applies only to legacy-watchers')
    if a.profile!='host-dcomp-resource':raise RuntimeError('No-VFS candidate supports only current host-dcomp-resource profile')
    required=[exe,exe.parent/'ru-RU/explorer.exe.mui',win/'System32/twinui.pcshell.dll']
    for f in required:
        if not f.is_file():raise RuntimeError('Required file absent: '+str(f))
    kernel=C.WinDLL('kernel32',use_last_error=True);user=C.WinDLL('user32',use_last_error=True);psapi=C.WinDLL('psapi',use_last_error=True)
    create=api(kernel,'CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,D,P,W.LPCWSTR,C.POINTER(SI),C.POINTER(PI)])
    getLog=lambda *args:False
    close=api(kernel,'CloseHandle',W.BOOL,[P]);term=api(kernel,'TerminateProcess',W.BOOL,[P,D]);wait=api(kernel,'WaitForSingleObject',D,[P,D]);exitCode=api(kernel,'GetExitCodeProcess',W.BOOL,[P,C.POINTER(D)])
    desktopCreate=api(user,'CreateDesktopW',P,[W.LPCWSTR,P,P,D,D,P]);desktopClose=api(user,'CloseDesktop',W.BOOL,[P])
    owner=api(user,'GetWindowThreadProcessId',D,[P,C.POINTER(D)]);cls=api(user,'GetClassNameW',C.c_int,[P,W.LPWSTR,C.c_int]);CB=C.WINFUNCTYPE(W.BOOL,P,P);enum=api(user,'EnumDesktopWindows',W.BOOL,[P,CB,P])
    enumModules=api(psapi,'EnumProcessModulesEx',W.BOOL,[P,P,D,C.POINTER(D),D]);mappedName=api(psapi,'GetMappedFileNameW',D,[P,P,W.LPWSTR,D])
    lab=base/'Lab/HostMultitaskingCompat';patch=json.loads((lab/'patch-info.json').read_text(encoding='utf-8'))
    if hashlib.sha256((win/'System32/twinui.pcshell.dll').read_bytes()).hexdigest()!=patch['sourceSha256']:raise RuntimeError('Host PCSHELL changed')
    si=SI();si.cb=C.sizeof(si)
    if a.preflight:
        name='CodexVfsPreflight_'+uuid.uuid4().hex;desk=desktopCreate(name,None,None,0,0x1ff,None)
        if not desk:raise C.WinError(C.get_last_error())
        si.desktop='WinSta0\\'+name;si.flags=1;si.show=0
    else:si.desktop='WinSta0\\Default'
    resourceHook=a.profile.endswith('-resource') or a.profile=='legacy-watchers'
    if a.theme10 and a.profile!='host-dcomp-resource':
        raise RuntimeError('Old process-private visual style is only prepared for host-dcomp-resource')
    if a.xaml_quirk and not resourceHook:
        raise RuntimeError('Scoped XAML compatibility requires a resource-enabled profile')
    jobSpec=importlib.util.spec_from_file_location('direct_child_job',base/'Lab/DirectLaunchLifecycle/ChildJob.py');jobModule=importlib.util.module_from_spec(jobSpec);jobSpec.loader.exec_module(jobModule)
    childJob=jobModule.ChildJob(breakaway_children=not a.preflight)
    childJob.create_suspended(exe,subprocess.list2cmdline([str(exe)]),si,pi,exe.parent)
    birth=C.c_uint64();ended=C.c_uint64();kernelTime=C.c_uint64();userTime=C.c_uint64()
    if not api(kernel,'GetProcessTimes',W.BOOL,[P,P,P,P,P])(pi.process,C.byref(birth),C.byref(ended),C.byref(kernelTime),C.byref(userTime)):raise C.WinError(C.get_last_error())
    state['birthFileTime']=str(birth.value);state['childJobAssignedBeforeResume']=True;state['liveUserChildrenIndependent']=not a.preflight
    packageName=C.create_unicode_buffer(2048);packageLength=D(len(packageName))
    packageError=api(kernel,'GetPackageFullName',C.c_int32,[P,C.POINTER(D),W.LPWSTR])(pi.process,C.byref(packageLength),packageName)
    state['childPackageIdentity']={'error':packageError,'fullName':packageName.value if packageError==0 else None}
    bootstrap=None
    if resourceHook:
        import importlib.util
        spec=importlib.util.spec_from_file_location('resource_bootstrap',base/'Launch-ResourceCompat.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        bootstrap=module.prepare_resource_hook(pi,exe,base/'Lab/ResourceCompat/FactoryWrapper/RSCW10.dll')
        nativeDcompSpec=importlib.util.spec_from_file_location('native_pcs_dcomp',base/'Lab/NativeHostPCSCompat/Launch-NativeDcomp.py');nativeDcompModule=importlib.util.module_from_spec(nativeDcompSpec);nativeDcompSpec.loader.exec_module(nativeDcompModule)
        state['nativeDcompHook']=nativeDcompModule.install_native_dcomp_compat(bootstrap)
        notifySpec=importlib.util.spec_from_file_location('notification_bootstrap',base/'Launch-NotificationCompat.py');notifyModule=importlib.util.module_from_spec(notifySpec);notifySpec.loader.exec_module(notifyModule)
        state['notificationHook']=notifyModule.install_notification_hook(bootstrap)
        inputSpec=importlib.util.spec_from_file_location('input_switch_bootstrap',base/'Launch-InputSwitchCompat.py');inputModule=importlib.util.module_from_spec(inputSpec);inputSpec.loader.exec_module(inputModule)
        state['inputSwitchHook']=inputModule.install_input_switch_compat(bootstrap)
        if a.profile=='host-dcomp-resource':
            classicSpec=importlib.util.spec_from_file_location('classic_context_bootstrap',base/'Launch-ClassicContextMenuCompat.py');classicModule=importlib.util.module_from_spec(classicSpec);classicSpec.loader.exec_module(classicModule)
            state['classicContextHook']=classicModule.install_classic_context_menu(bootstrap)
            winxSpec=importlib.util.spec_from_file_location('winx_bootstrap',base/'Lab/NativeWinXCompat/Launch-WinXNative.py');winxModule=importlib.util.module_from_spec(winxSpec);winxSpec.loader.exec_module(winxModule)
            state['winXHook']=winxModule.install_winx_compat(bootstrap)
            # V2 checks the physical PCS image already loaded by WinX.
            menuSpec=importlib.util.spec_from_file_location('menu_square_bootstrap',base/'Lab/NativeMenuSquareV2/Launch-MenuSquareV2.py');menuModule=importlib.util.module_from_spec(menuSpec);menuSpec.loader.exec_module(menuModule)
            state['menuSquareHook']=menuModule.install_menu_square_hook(bootstrap)
            if a.icons10:
                iconHookSpec=importlib.util.spec_from_file_location('icon_direct_bootstrap',base/'Lab/NoVfsShellCompat/Install-Icons.py');iconHookModule=importlib.util.module_from_spec(iconHookSpec);iconHookSpec.loader.exec_module(iconHookModule)
                state['iconResourceHook']=iconHookModule.install_icons(bootstrap)
                state['shellUXRevision']=8
        if a.theme10:
            themeSpec=importlib.util.spec_from_file_location('theme10_bootstrap',base/'Launch-Theme10Compat.py');themeModule=importlib.util.module_from_spec(themeSpec);themeSpec.loader.exec_module(themeModule)
            state['theme10Hook']=themeModule.install_theme10(bootstrap)
        if a.control_theme10:
            controlSpec=importlib.util.spec_from_file_location('control_theme10_bootstrap',base/'Lab/ControlThemeBootstrap/Launch-ControlTheme10.py');controlModule=importlib.util.module_from_spec(controlSpec);controlSpec.loader.exec_module(controlModule)
            state['controlTheme10Hook']=controlModule.install_control_theme10(bootstrap)
        if a.hybrid_theme10:
            hybridSpec=importlib.util.spec_from_file_location('hybrid_theme10_bootstrap',base/'Lab/HybridThemeBootstrap/Launch-HybridTheme10.py');hybridModule=importlib.util.module_from_spec(hybridSpec);hybridSpec.loader.exec_module(hybridModule)
            state['hybridTheme10Hook']=hybridModule.install_hybrid_theme10(bootstrap)
            themeMenuSpec=importlib.util.spec_from_file_location('theme_menu_bootstrap',base/'Lab/NativeThemeMenuBootstrap/Launch-ThemeMenu.py');themeMenuModule=importlib.util.module_from_spec(themeMenuSpec);themeMenuSpec.loader.exec_module(themeMenuModule)
            state['themeMenuHook']=themeMenuModule.install_theme_menu(bootstrap,state['hybridTheme10Hook'])
            state['shellUXRevision']=12
        if a.preflight and (a.control_theme10 or a.hybrid_theme10):
            if not a.control_theme10:
                controlSpec=importlib.util.spec_from_file_location('control_theme10_bootstrap',base/'Lab/ControlThemeBootstrap/Launch-ControlTheme10.py');controlModule=importlib.util.module_from_spec(controlSpec);controlSpec.loader.exec_module(controlModule)
            state['themeFolderProbePrepared']=controlModule.prepare_control_theme10_probe(bootstrap)
        if a.xaml_quirk:
            xamlSpec=importlib.util.spec_from_file_location('xaml_quirk_bootstrap',base/'Launch-XamlQuirkCompat.py');xamlModule=importlib.util.module_from_spec(xamlSpec);xamlSpec.loader.exec_module(xamlModule)
            state['xamlQuirkHook']=xamlModule.install_xaml_quirk_hook(bootstrap)
        if a.profile=='legacy-watchers':
            # Resolve this private module before installing its import hook. The
            # primary thread is still held before Explorer's entrypoint.
            bootstrap.load_library(base/'Lab/XamlComponentCompat/twinui.pcshell.dll')
            delegateSpec=importlib.util.spec_from_file_location('view_delegate_bootstrap',base/'Launch-ViewDelegateCompat.py');delegateModule=importlib.util.module_from_spec(delegateSpec);delegateSpec.loader.exec_module(delegateModule)
            state['viewDelegateHook']=delegateModule.install_view_delegate_hook(bootstrap)
            frameSpec=importlib.util.spec_from_file_location('appframe_manager_bootstrap',base/'Launch-AppFrameManagerCompat.py');frameModule=importlib.util.module_from_spec(frameSpec);frameSpec.loader.exec_module(frameModule)
            state['appFrameManagerHook']=frameModule.install_appframe_manager_hook(bootstrap)
            factorySpec=importlib.util.spec_from_file_location('legacy_factory_bootstrap',base/'Launch-LegacyClassFactoryCompat.py');factoryModule=importlib.util.module_from_spec(factorySpec);factorySpec.loader.exec_module(factoryModule)
            state['legacyFactoryHook']=factoryModule.install_legacy_class_factory_hook(bootstrap)
            if a.no_legacy_touchpad:
                touchpadSpec=importlib.util.spec_from_file_location('touchpad_bootstrap',base/'Launch-TouchpadCompat.py');touchpadModule=importlib.util.module_from_spec(touchpadSpec);touchpadSpec.loader.exec_module(touchpadModule)
                state['touchpadHook']=touchpadModule.install_touchpad_compat(bootstrap)
            coreSpec=importlib.util.spec_from_file_location('coreui_bootstrap',base/'Launch-CoreUICompat.py');coreModule=importlib.util.module_from_spec(coreSpec);coreSpec.loader.exec_module(coreModule)
            state['coreUIHook']=coreModule.install_coreui_compat(bootstrap)
            keyboardSpec=importlib.util.spec_from_file_location('keyboard_bootstrap',base/'Launch-KeyboardCompat.py');keyboardModule=importlib.util.module_from_spec(keyboardSpec);keyboardSpec.loader.exec_module(keyboardModule)
            state['keyboardHook']=keyboardModule.install_keyboard_compat(bootstrap)
        state['resourceHook']=bootstrap.events
    if a.capture_debug:
        from ChildDiagnostics import ChildDiagnostics
        traceFile=base/('Lab/HostMultitaskingCompat/trace-breakpoints.json' if a.profile.startswith('host-dcomp') else 'Lab/XamlComponentCompat/trace-breakpoints.json')
        trace=json.loads(traceFile.read_text(encoding='utf8')) if traceFile.is_file() else []
        debugger=ChildDiagnostics(pi.process,pi.pid,run/'debug.jsonl',breakpoints=trace)
    if bootstrap:bootstrap.resume_primary()
    elif a.capture_debug:api(kernel,'ResumeThread',D,[P])(pi.thread)
    state.update(status='running',pid=pi.pid,exe=str(exe),helperPid=os.getpid(),desktop=si.desktop,createdAt=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()));report()
    (run/'child-ready').write_text(str(pi.pid),encoding='ascii')
    hybridNext=0;hybridLast=None;themeMenuLast=None
    if a.hybrid_theme10:
        themeMenuAddress=int(state['themeMenuHook']['helperBase'],16)+themeMenuModule.exports(base/'Lab/NativeThemeMenuCompat/ThemeMenuCompat.dll')['ThemeMenuState']
        hybridAddress=int(state['hybridTheme10Hook']['helperBase'],16)+hybridModule.exports(base/'Lab/ThemeFolderHybridCompat/ThemeFolderHybrid.dll')['ThemeFolderHybridState']
    deadline=time.monotonic()+8 if a.preflight else float('inf')
    moduleGateNext=time.monotonic()+2
    with (run/'transport.log').open('a',encoding='utf-8') as log:
        while time.monotonic()<deadline and wait(pi.process,0 if debugger else 200)==258:
            if time.monotonic()>=moduleGateNext:
                moduleGateNext=time.monotonic()+5
                gateMods=(P*2048)();gateNeeded=D();gatePaths=[]
                if not enumModules(pi.process,gateMods,C.sizeof(gateMods),C.byref(gateNeeded),3) or gateNeeded.value>C.sizeof(gateMods):
                    raise RuntimeError('Direct runtime module census failed')
                for gm in gateMods[:gateNeeded.value//C.sizeof(P)]:
                    gb=C.create_unicode_buffer(4096)
                    if not mappedName(pi.process,gm,gb,4096):raise RuntimeError('Direct module physical path unavailable')
                    gatePaths.append(gb.value)
                gatePCS=[x for x in gatePaths if x.lower().endswith('\\twinui.pcshell.dll')]
                if len(gatePCS)!=1 or not gatePCS[0].lower().endswith('\\windows\\system32\\twinui.pcshell.dll') or any('usvfs' in x.casefold() for x in gatePaths):
                    raise RuntimeError('Direct runtime requires one native PCS and zero USVFS modules')
                state['pcsImageCount']=1;state['usvfsModuleCount']=0;state['directModuleGateVerified']=True;report()
            if debugger:debugger.pump(100)
            b=C.create_string_buffer(8192)
            while getLog(b,len(b),False):log.write(b.value.decode('utf-8',errors='replace')+'\n')
            log.flush()
            if a.hybrid_theme10 and time.monotonic()>=hybridNext:
                hybridNext=time.monotonic()+2
                menuState=struct.unpack('<16I12Q',bootstrap.read(themeMenuAddress,160))
                menuNow=tuple(menuState[i]for i in (3,4,5,6,9,10,14))
                if menuNow!=themeMenuLast:
                    state['themeMenuRuntime']=dict(zip(['active','mappedPlain','mappedPCS','mappedShell','generationRejected','failures','quarantined'],menuNow));report();themeMenuLast=menuNow
                if menuState[0]!=160 or menuState[1]!=1 or menuState[3]!=1 or menuState[9] or menuState[10] or menuState[14]:
                    raise RuntimeError('Menu theme ownership/generation failed; discard exact owned Explorer')
                hybridState=struct.unpack('<16I12Q',bootstrap.read(hybridAddress,160))
                hybridCurrent=struct.unpack('<Q',bootstrap.read(state['hybridTheme10Hook']['CurrentThemePointerAddress'],8))[0]
                if hybridCurrent!=hybridState[16]:
                    raise RuntimeError('Process current theme provider changed; discarding exact owned hybrid Explorer for safe recovery')
                hybridNow=(hybridState[3],hybridState[4],hybridState[5],hybridState[6],hybridState[10],hybridState[14],hybridState[15])
                if hybridNow!=hybridLast:
                    state['hybridTheme10Runtime']=dict(zip(['active','fullTheme','fallback8','fallback11','failures','nativeHeaderFallbacks','generationRejected'],hybridNow));report();hybridLast=hybridNow
                if hybridState[0]!=160 or hybridState[1]!=2 or hybridState[3]!=1 or hybridState[4]!=1 or hybridState[15]:
                    raise RuntimeError('Hybrid theme ownership/generation changed; discarding exact owned Explorer for safe recovery')
            if (run/'stop').exists():raise RuntimeError('Launcher requested stop')
    code=D();exitCode(pi.process,C.byref(code));state['exitCode']=code.value
    mods=(P*2048)();needed=D();paths=[]
    if enumModules(pi.process,mods,C.sizeof(mods),C.byref(needed),3):
        for m in mods[:min(needed.value//C.sizeof(P),2048)]:
            b=C.create_unicode_buffer(4096);mappedName(pi.process,m,b,4096);paths.append(b.value)
    state['mappedModules']=paths
    if a.preflight:
        windows=[]
        @CB
        def cb(h,p):
            pid=D();owner(h,C.byref(pid))
            if pid.value==pi.pid:
                b=C.create_unicode_buffer(256);cls(h,b,256);windows.append(b.value)
            return True
        enum(desk,cb,None);state['windowClasses']=sorted(set(windows))
        targets=['\\Windows\\System32\\twinui.pcshell.dll'] if a.profile.startswith('host-dcomp') else ['\\Lab\\WindowGroupCompat\\twinui.pcshell.dll','\\Lab\\WindowGroupCompat\\U32W10.dll']
        if a.profile=='legacy-watchers':targets=['\\Lab\\XamlComponentCompat\\twinui.pcshell.dll','\\Lab\\WindowGroupCompat\\U32W10.dll']
        if code.value!=259 or not {'Progman','Shell_TrayWnd'}<=set(windows) or not all(any(s.lower().endswith(t.lower()) for s in paths) for t in targets):
            raise RuntimeError('Hidden preflight did not prove required lab DLLs and desktop/tray creation')
        if a.control_theme10 or a.hybrid_theme10:
            state['themeFolderProof']=controlModule.probe_control_theme10(bootstrap,preflight=True,desktop_handle=desk,desktop_name=name)
        if a.hybrid_theme10:
            finalHybrid=struct.unpack('<16I12Q',bootstrap.read(hybridAddress,160))
            finalCurrent=struct.unpack('<Q',bootstrap.read(state['hybridTheme10Hook']['CurrentThemePointerAddress'],8))[0]
            state['hybridTheme10FolderRuntime']={'oldCurrentPreserved':finalCurrent==finalHybrid[16],'fallback8':finalHybrid[5],'fallback11':finalHybrid[6],'failures':finalHybrid[10],'generationRejected':finalHybrid[15]}
            if finalCurrent!=finalHybrid[16] or finalHybrid[3]!=1 or finalHybrid[4]!=1 or finalHybrid[10] or finalHybrid[15] or not finalHybrid[5] or not finalHybrid[6]:
                raise RuntimeError('Actual folder did not prove the two native color fallbacks with old theme preserved: '+str(state['hybridTheme10FolderRuntime']))
        pcsImages=[x for x in paths if x.lower().endswith('\\twinui.pcshell.dll')]
        if len(pcsImages)!=1 or any('usvfs' in x.casefold()for x in paths):raise RuntimeError('Direct preflight requires exactly one PCS and zero USVFS modules')
        state['pcsImageCount']=len(pcsImages);state['usvfsModuleCount']=0
        state['status']='preflight-pass'
    else:state['status']='child-exited'
    success=True
except Exception as e:state.update(status='error',error=str(e))
finally:
    if pi.process:
        if a.preflight or not success:term(pi.process,0)
        if debugger:
            end=time.monotonic()+2
            while time.monotonic()<end and wait(pi.process,0)==258:debugger.pump(100)
            debugger.close()
        wait(pi.process,3000);close(pi.thread);close(pi.process)
    if childJob:
        try:childJob.shutdown();state['ownedJobDrained']=True
        except Exception as e:state.update(status='error',cleanupError=str(e));success=False
    if connected:disconnect()
    if params:parametersFree(params)
    if desk:desktopClose(desk)
    if dll_dir:dll_dir.close()
    report()
sys.exit(0 if success else 1)
