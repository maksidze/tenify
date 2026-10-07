"""Exact old TabTip caller adaptation to native CoreKeyboardManager; memory only."""
from pathlib import Path
import hashlib,json,struct,sys,ctypes as C,importlib.util
from ctypes import wintypes as W
BASE=Path(__file__).resolve().parent
WORK=BASE.parent.parent/'work'
sys.path.insert(0,str(WORK/'pylib'));import pefile,capstone
PCS_SHA='d3b5243f814e4e2a854abf8bff9c6d449ab332edb0d8a87cd02e75041d3cb1e1'
NATIVE_SHA='267592e67d0223f5f333254adf891b8c2ff478e0d48e244ffd355dae36eee563'
PDB_SHA='c92e6162f8e731bb632f5d3ccd403902af8d40e3cab90abe026d88138b36aeb6'
SITES_SHA='0842e4d1e802adab2636698198dd8b1e4fef50f272d84d32ba20aebadc255782'
OVERFLOWS={0x3cd3bc:(0x3cd3b9,bytes.fromhex('488b074c8b7070'),bytes.fromhex('488b074c8bb080000000')),
           0x3d448c:(0x3d4489,bytes.fromhex('488b01488b4078'),bytes.fromhex('488b01488b8088000000'))}
def _check(path,sha):
    if hashlib.sha256(path.read_bytes()).hexdigest()!=sha:raise RuntimeError('Keyboard ABI build mismatch: '+str(path))
def _paused(b):
    if not b.primary_suspended or not b.entry_restored or b.attached:raise RuntimeError('Keyboard patch requires owned entry-paused child, debugger detached')
def _mapped(b,base,path):
    spec=importlib.util.spec_from_file_location('KeyboardMappedIdentity',BASE/'Launch-TouchpadCompat.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m.mapped_file_identity(b,base,path)
def _reljump(source,destination):
    disp=destination-source-5
    if not -(1<<31)<=disp<(1<<31):raise RuntimeError('Near trampoline out of rel32 range')
    return b'\xe9'+struct.pack('<i',disp)
def _near(b,anchor):
    start=anchor&~0xffff
    for distance in range(0x1000000,0x3000000,0x10000):
        for address in (start+distance,start-distance):
            block=b.alloc(b.pi.process,address,4096,0x3000,4)
            if block:return int(block)
    raise RuntimeError('Bounded near RX allocation unavailable')
def static_patch_plan():
    pcsPath=BASE/'Lab/XamlComponentCompat/twinui.pcshell.dll';sitesPath=WORK/'keyboard-compat/pcs-manager-callsites.json'
    _check(pcsPath,PCS_SHA);_check(sitesPath,SITES_SHA);image=pefile.PE(str(pcsPath));rows=json.loads(sitesPath.read_text());plan=[]
    if len(rows)!=57:raise RuntimeError('Verified manager caller set count mismatch')
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    for row in rows:
        rva=int(row['rva'],16);old=bytes.fromhex(row['bytes'])
        if image.get_data(rva,len(old))!=old or row['nativeSlot'] is None:raise RuntimeError('Caller report/instruction mismatch')
        instructions=list(decoder.disasm(old,rva))
        if len(instructions)!=1 or instructions[0].mnemonic!='mov' or instructions[0].size!=len(old):raise RuntimeError('Unexpected manager load encoding')
        if row['oldSlot']==row['nativeSlot']:continue
        if rva in OVERFLOWS:
            start,window,replay=OVERFLOWS[rva]
            if image.get_data(start,len(window))!=window:raise RuntimeError('Overflow predecessor window mismatch')
            decoded=list(decoder.disasm(window,start));newDecoded=list(decoder.disasm(replay,0))
            if len(decoded)!=2 or len(newDecoded)!=2 or any(i.mnemonic!='mov' for i in decoded+newDecoded):raise RuntimeError('Unsafe trampoline replay')
            plan.append({'rva':start,'old':window,'replay':replay,'oldSlot':row['oldSlot'],'nativeSlot':row['nativeSlot']})
        else:
            offset=row['dispOffset'];size=row['dispSize'];value=row['nativeSlot']*8
            if size not in (1,4) or (size==1 and value>127):raise RuntimeError('Unplanned displacement expansion')
            new=old[:offset]+int(value).to_bytes(size,'little',signed=True)+old[offset+size:]
            plan.append({'rva':rva,'old':old,'new':new,'oldSlot':row['oldSlot'],'nativeSlot':row['nativeSlot']})
    if len(plan)!=52 or sum('replay' in x for x in plan)!=2:raise RuntimeError('Verified patch count mismatch')
    # No old branch may enter the middle of the replaced two-MOV window.
    # These private methods are intra-function straight-line call sites.
    decoder.detail=True
    from capstone.x86_const import X86_OP_IMM
    for site in (x for x in plan if 'replay' in x):
        start=site['rva'];end=start+len(site['old'])
        fn=next((f.struct for f in image.DIRECTORY_ENTRY_EXCEPTION if f.struct.BeginAddress<=start<f.struct.EndAddress),None)
        if not fn:raise RuntimeError('Trampoline window has no enclosing PCS function')
        for instruction in decoder.disasm(image.get_data(fn.BeginAddress,fn.EndAddress-fn.BeginAddress),fn.BeginAddress):
            if instruction.mnemonic.startswith(('j','call')) and instruction.operands and instruction.operands[0].type==X86_OP_IMM:
                if start<instruction.operands[0].imm<end:raise RuntimeError('Unsafe incoming branch into trampoline window')
    return plan
def install_keyboard_compat(bootstrap):
    _paused(bootstrap);plan=static_patch_plan()
    nativePath=Path('C:/Windows/System32/Windows.UI.Core.TextInput.dll');pcsPath=BASE/'Lab/XamlComponentCompat/twinui.pcshell.dll'
    _check(nativePath,NATIVE_SHA);_check(WORK/'compat-research/host-textinput/Windows.UI.Core.TextInput.pdb',PDB_SHA)
    nativeModules=[(n,b) for n,b in bootstrap.modules().items() if n.endswith('\\windows.ui.core.textinput.dll')]
    if not nativeModules:
        bootstrap.load_library(nativePath);nativeModules=[(n,b) for n,b in bootstrap.modules().items() if n.endswith('\\windows.ui.core.textinput.dll')]
    pcsModules=[(n,b) for n,b in bootstrap.modules().items() if n.endswith('\\twinui.pcshell.dll')]
    if len(nativeModules)!=1 or len(pcsModules)!=1:raise RuntimeError('Ambiguous manager/PCS module identity')
    _,pcs=pcsModules[0];_,native=nativeModules[0]
    identities={'pcs':_mapped(bootstrap,pcs,pcsPath),'native':_mapped(bootstrap,native,nativePath)}
    image=pefile.PE(str(nativePath))
    for rva in (0x639a0,0x4bdb0):
        if bootstrap.read(native+rva,16)!=image.get_data(rva,16):raise RuntimeError('Native manager getter altered')
    for site in plan:
        if bootstrap.read(pcs+site['rva'],len(site['old']))!=site['old']:raise RuntimeError('Manager caller already altered '+hex(site['rva']))
    block=0;applied=[];records=[]
    try:
        block=_near(bootstrap,pcs+0x3cd3b9);cursor=0
        for site in plan:
            address=pcs+site['rva'];new=site.get('new');trampoline=None
            if 'replay' in site:
                trampoline=block+cursor;code=site['replay']+_reljump(trampoline+len(site['replay']),address+len(site['old']))
                bootstrap.patch(trampoline,code)
                if bootstrap.read(trampoline,len(code))!=code:raise RuntimeError('Trampoline readback failed')
                new=_reljump(address,trampoline)+b'\x90'*(len(site['old'])-5);cursor+=64
            records.append({'rva':hex(site['rva']),'original':site['old'].hex(),'replacement':new.hex(),'oldSlot':site['oldSlot'],'nativeSlot':site['nativeSlot'],'trampoline':hex(trampoline) if trampoline else None})
        previous=W.DWORD()
        if not bootstrap.protect(bootstrap.pi.process,block,4096,0x20,C.byref(previous)) or not bootstrap.flush(bootstrap.pi.process,block,4096):raise C.WinError(C.get_last_error())
        for record in records:
            address=pcs+int(record['rva'],16);new=bytes.fromhex(record['replacement'])
            bootstrap.patch(address,new,True);applied.append(record)
            if bootstrap.read(address,len(new))!=new:raise RuntimeError('Manager load patch readback failed')
    except BaseException:
        for record in reversed(applied):bootstrap.patch(pcs+int(record['rva'],16),bytes.fromhex(record['original']),True)
        if block:bootstrap.free(bootstrap.pi.process,block,0,0x8000)
        raise
    result={'type':'coreKeyboardManagerCallerABI','ownedPid':bootstrap.pi.pid,'pcsBase':hex(pcs),'pcsSha256':PCS_SHA,'nativeTextInputSha256':NATIVE_SHA,'nativeTextInputPdbSha256':PDB_SHA,'mappedIdentities':identities,'verifiedLoads':57,'changedLoads':52,'nearRxBlock':hex(block),'patches':records,'processMemoryOnly':True,'globalIidAlias':False,'nativeObjectOrVtableModified':False,'obsoleteDelegationEventMapped':False,'trampolineCalls':False,'originalCfgCallsPreserved':True}
    bootstrap.events.append(result);return result
def restore_keyboard_compat(bootstrap,result):
    _paused(bootstrap)
    if result['ownedPid']!=bootstrap.pi.pid:raise RuntimeError('Keyboard counterpatch owned PID mismatch')
    pcs=int(result['pcsBase'],16)
    _mapped(bootstrap,pcs,BASE/'Lab/XamlComponentCompat/twinui.pcshell.dll')
    for row in result['patches']:
        new=bytes.fromhex(row['replacement'])
        if bootstrap.read(pcs+int(row['rva'],16),len(new))!=new:raise RuntimeError('Keyboard counterpatch foreign modification')
    for row in reversed(result['patches']):
        address=pcs+int(row['rva'],16);original=bytes.fromhex(row['original']);bootstrap.patch(address,original,True)
        if bootstrap.read(address,len(original))!=original:raise RuntimeError('Keyboard counterpatch readback failed')
    if not bootstrap.free(bootstrap.pi.process,int(result['nearRxBlock'],16),0,0x8000):raise C.WinError(C.get_last_error())
    return {'restored':True,'ownedPid':bootstrap.pi.pid,'loads':len(result['patches'])}

