import sys,json,hashlib
from pathlib import Path
sys.path.insert(0,'work/pylib')
import pefile,capstone
path=Path('outputs/Windows10-Components/Lab/HostMultitaskingCompat/twinui.pcshell.dll')
p=pefile.PE(str(path));d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
points=[(0x1e2062,'MakeTaskViewFrameReturn','RAX constructed frame/output; before push'),(0x696978,'FrameInitialize','RCX TaskViewFrame'),(0x6969de,'WorkAreaAsyncReturned','RAX points to IAsyncAction; action=[RAX]'),(0x6969e1,'WaitWorkArea','RCX=IAsyncAction'),(0x6969e6,'WaitWorkAreaReturned','EAX wait HRESULT (caller does not test)'),(0x6947e7,'CoWait','ECX8 flags; EDXffffffff timeout; R8D1; R9 eventarray'),(0x6947ee,'CoWaitReturned','EAX HRESULT'),(0x285bec,'GetDisplayMonitorInfoAsync','RCX points to async output'),(0x285bf1,'GetDisplayMonitorInfoAsyncReturned','coroutine async slot output'),(0x285c44,'AwaitSuspend','RCX await_adapter; RDX coroutine handle'),(0x285c49,'AwaitSuspendReturned','AL suspension bool'),(0x285c77,'AwaitResume','collection output'),(0x696a67,'XamlExplorerHostCtor','first window ctor AFTER wait'),(0x696ac9,'CreateTimelineControl','after host ctor/item collection'),(0x1e20f2,'PushFrame','vector end advances only after initialization')]
rows=[]
for rva,name,capture in points:
 i=next(d.disasm(p.get_data(rva,16),rva))
 rows.append(dict(rva=rva,rvaHex=hex(rva),name=name,capture=capture,guard=bytes(i.bytes).hex(),instruction=i.mnemonic+' '+i.op_str))
iat={x.address-p.OPTIONAL_HEADER.ImageBase:(entry.dll.decode()+'!'+(x.name.decode() if x.name else '#'+str(x.ordinal))) for entry in p.DIRECTORY_ENTRY_IMPORT for x in entry.imports}
assert iat[0x6947e7+7+0xa1a8a].endswith('!CoWaitForMultipleHandles')
report=dict(module=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),points=rows,proof=['CreateFrames sets monitorCount before calling CreateFrameForMonitor.','CreateFrameForMonitor calls MakeTaskViewFrame then pushes result only after initialize/getters.','RuntimeClassInitialize starts UpdateWorkAreaAsync and synchronously waits indefinitely with COWAIT_DISPATCH_CALLS=8.','UpdateWorkAreaAsync awaits WindowsUdk.UI.Shell.DisplayMonitorInfoCollection.GetCurrentAsync.','Window/XAML ctor follows successful or failed returned wait (HRESULT ignored here).'],limitations=['No live process access. No evidence yet that PID10488 is in this wait.','MonitorCount1 plus zero frames is compatible with this wait, but is not proof.'])
Path('work/taskview-frame-wait-trace-points.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print('Saved',len(rows),'guarded read-only trace proposals; CoWait import confirmed')

