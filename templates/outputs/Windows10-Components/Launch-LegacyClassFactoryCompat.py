"""Restore a relocated legacy COM class factory only in the owned Explorer."""
from pathlib import Path
import hashlib,json,struct,sys,winreg
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'))
import pefile

def install_legacy_class_factory_hook(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored or bootstrap.attached:
        raise RuntimeError('Legacy factory routing requires owned entry-paused, debugger-detached child')
    lab=BASE/'Lab/LegacyClassFactoryCompat'
    metadata=json.loads((lab/'adapter-metadata.json').read_text(encoding='utf8'))
    helper=lab/'LegacyClassFactoryCompat.dll'
    twinui=BASE/'Image/4/Windows/System32/twinui.dll'
    pcs=BASE/'Lab/XamlComponentCompat/twinui.pcshell.dll'
    manager=BASE/'Lab/AppFrameManagerCompat/AppFrameManagerCompat.dll'
    for path,key in [(helper,'helperSha256'),(twinui,'oldTwinuiSha256'),(pcs,'oldPCShellSha256'),(manager,'managerAdapterSha256')]:
        if hashlib.sha256(path.read_bytes()).hexdigest()!=metadata[key]:
            raise RuntimeError('Legacy factory build mismatch: '+str(path))
    with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT,r'CLSID\{19227dc0-fc88-4aaa-8c2d-a0db913aa2ff}\InprocServer32') as key:
        registered=winreg.ExpandEnvironmentStrings(winreg.QueryValueEx(key,None)[0])
    if str(Path(registered).resolve()).lower()!=str(Path('C:/Windows/System32/twinui.pcshell.dll').resolve()).lower():
        raise RuntimeError('Unsupported ShellSnap COM registration')
    modules=bootstrap.modules()
    pcs_base=modules.get(str(pcs).lower());manager_base=modules.get(str(manager).lower())
    if not pcs_base or not manager_base:raise RuntimeError('Verified old PCShell and manager adapter must already be loaded')
    call=bytes.fromhex(metadata['callBytes']);call_rva=int(metadata['callRva'],16)
    if bootstrap.read(pcs_base+call_rva,len(call))!=call:raise RuntimeError('Trusted-component CoCreate caller changed')
    manager_image=pefile.PE(str(manager));manager_export=next(x.address for x in manager_image.DIRECTORY_ENTRY_EXPORT.symbols if x.name==b'AppFrameCoCreateInstance')
    site=pcs_base+0x544898;before=bootstrap.read(site,8)
    if struct.unpack('<Q',before)[0]!=manager_base+manager_export:raise RuntimeError('Expected established frame-manager adapter chain')
    image=pefile.PE(str(helper));exports={x.name.decode():x.address for x in image.DIRECTORY_ENTRY_EXPORT.symbols if x.name}
    module=bootstrap.load_library(helper)
    config=struct.pack('<IIQ',2064,1,struct.unpack('<Q',before)[0])+str(twinui).encode('utf-16-le').ljust(2048,b'\0')
    if len(config)!=2064:raise RuntimeError('Factory source path too long')
    bootstrap.patch(module+exports['LegacyFactoryConfig'],config)
    if bootstrap.read(module+exports['LegacyFactoryConfig'],len(config))!=config:raise RuntimeError('Factory configuration readback failed')
    after=struct.pack('<Q',module+exports['LegacyCoCreateInstance'])
    try:
        bootstrap.patch(site,after)
        if bootstrap.read(site,8)!=after:raise RuntimeError('Factory hook readback failed')
    except BaseException:
        bootstrap.patch(site,before);raise
    result={'type':'legacyClassFactory','class':'19227dc0-fc88-4aaa-8c2d-a0db913aa2ff','iid':'5fefbb8e-82c3-4ec4-93a0-05c4b9fcd4cd','context':hex(0x401),'source':str(twinui),'originalIat':hex(struct.unpack('<Q',before)[0]),'replacementIat':hex(struct.unpack('<Q',after)[0]),'previousAdapterPreserved':True,'systemRegistrationChanged':False}
    bootstrap.events.append(result);return result
