"""Exact old PCS/native CoreUI factory slot correction, owned child memory only."""
from pathlib import Path
import hashlib, json, struct, sys, uuid

BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent/'work/pylib'))
import pefile
PCS_SHA='d3b5243f814e4e2a854abf8bff9c6d449ab332edb0d8a87cd02e75041d3cb1e1'
CORE_SHA='145f3a951f5e92967dfd5e8e8641517ec8d1cacc4666f32a70e7d974d6b96338'
PDB_SHA='4363937a398f3558d1fa4c2659ce4e8b6093737e0c76579b14183c7455a30a95'
GUID='a7580172-832e-f62d-bf6e-9909fa194e1c'
CALL_RVA=0x4d9c78
OLD_BYTES=bytes.fromhex('488b4038')
NEW_BYTES=bytes.fromhex('488b4030')

def _hash(path,expected):
    if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
        raise RuntimeError('Unsupported CoreUI compatibility binary: '+str(path))

def install_coreui_compat(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored or bootstrap.attached:
        raise RuntimeError('CoreUI correction requires owned entry-paused child and detached bootstrap debugger')
    pcsPath=BASE/'Lab/XamlComponentCompat/twinui.pcshell.dll'
    corePath=Path('C:/Windows/System32/CoreUIComponents.dll')
    pdbPath=BASE.parent.parent/'work/compat-research/host-coreui/CoreUIComponents.pdb'
    _hash(pcsPath,PCS_SHA);_hash(corePath,CORE_SHA);_hash(pdbPath,PDB_SHA)
    corePe=pefile.PE(str(corePath))
    records=[]
    for item in corePe.DIRECTORY_ENTRY_DEBUG:
        raw=corePe.get_data(item.struct.AddressOfRawData,item.struct.SizeOfData)
        if raw[:4]==b'RSDS':records.append((str(uuid.UUID(bytes_le=raw[4:20])),struct.unpack_from('<I',raw,20)[0]))
    if records!=[(GUID,1)]:raise RuntimeError('Native CoreUI RSDS mismatch')
    # The matched PDB is immutable hash-guarded; PE hash pins the actual vtable.
    pe=pefile.PE(str(pcsPath))
    if pe.get_data(CALL_RVA,4)!=OLD_BYTES:raise RuntimeError('PCS disk call instruction mismatch')
    coreCandidates=[(n,b) for n,b in bootstrap.modules().items() if n.endswith('\\coreuicomponents.dll')]
    if not coreCandidates:
        bootstrap.load_library(corePath)
        coreCandidates=[(n,b) for n,b in bootstrap.modules().items() if n.endswith('\\coreuicomponents.dll')]
    pcsCandidates=[(n,b) for n,b in bootstrap.modules().items() if n.endswith('\\twinui.pcshell.dll')]
    if len(pcsCandidates)!=1 or len(coreCandidates)!=1:raise RuntimeError('Ambiguous PCS/CoreUI module identity')
    # Query physical image sections outside child VFS, not reported virtual paths.
    import importlib.util
    spec=importlib.util.spec_from_file_location('CoreUIMappedIdentity',BASE/'Launch-TouchpadCompat.py')
    identity=importlib.util.module_from_spec(spec);spec.loader.exec_module(identity)
    pcsName,pcs=pcsCandidates[0];coreName,core=coreCandidates[0]
    pcsPhysical=identity.mapped_file_identity(bootstrap,pcs,pcsPath)
    corePhysical=identity.mapped_file_identity(bootstrap,core,corePath)
    if bootstrap.read(pcs+CALL_RVA,4)!=OLD_BYTES:raise RuntimeError('PCS memory call instruction mismatch or already patched')
    # Validate native store vtable targets themselves, in addition to immutable file hash.
    for rva in (0x173c0,0x16580):
        if bootstrap.read(core+rva,16)!=corePe.get_data(rva,16):raise RuntimeError('Native CoreUI method already altered')
    try:
        bootstrap.patch(pcs+CALL_RVA+3,b'\x30',True)
        if bootstrap.read(pcs+CALL_RVA,4)!=NEW_BYTES:raise RuntimeError('CoreUI slot patch readback mismatch')
    except BaseException:
        bootstrap.patch(pcs+CALL_RVA+3,b'\x38',True)
        raise
    result={'type':'coreUIMessagePortFactorySlot','pcsSha256':PCS_SHA,'nativeCoreUISha256':CORE_SHA,
            'nativeCoreUIPdbSha256':PDB_SHA,'nativeCoreUIPdbGuid':GUID,'nativeCoreUIPdbAge':1,
            'pcsReportedModule':pcsName,'coreReportedModule':coreName,'pcsPhysicalIdentity':pcsPhysical,
            'corePhysicalIdentity':corePhysical,'instructionRva':hex(CALL_RVA),'patchedByteRva':hex(CALL_RVA+3),
            'oldInstruction':OLD_BYTES.hex(),'newInstruction':NEW_BYTES.hex(),'oldFactorySlot':7,'nativeFactorySlot':6,
            'method':'MessagePortStoreCreate(out IExportMessagePortStore**)','processMemoryOnly':True,
            'reason':'Removed CreateNavigationWindow overload shifted native factory methods by one slot'}
    bootstrap.events.append(result)
    return result
