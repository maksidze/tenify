from pathlib import Path
import sys,json,hashlib
sys.path.insert(0,'work/pylib');import pefile,capstone
path=Path('outputs/Windows10-Components/Lab/HostMultitaskingCompat/twinui.pcshell.dll');p=pefile.PE(str(path));s=json.load(open('work/compat-research/host-twinui/all-public-symbols.json'));ns={r['rva']:r['name'] for r in s};d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
points=[(0x21d50,'SchedulerQueue','RCX=scheduler interface; wholeBase=RCX-60; manager=[RCX+40], opaqueTaskpoolContext=DWORD[RCX+a0]'),(0x21de2,'CallbackMarshalResult','EAX=callback CMarshalStream creation HR'),(0x21e1e,'ManagerMarshalResult','EAX=manager CMarshalStream creation HR'),(0x21e91,'ShTaskQueue','ECX1,EDX2,R8D opaqueTaskpoolContext,[rsp+20]task'),(0x21e9d,'ShTaskQueueResult','EAX queue HR'),(0x2301a0,'TaskRunThunk','RCX=task COM object; +10callbackstream,+18managerstream'),(0x133e94,'TaskRun','RCX=address of task captures task+10'),(0x133f2c,'CallbackAgileResolve','EAX=IAgileReference::Resolve(callbackIID)HR;out[rbp+38]'),(0x133fce,'ManagerAgileResolve','EAX=IAgileReference::Resolve(managerIID)HR;out[rbp+30]'),(0x133ffe,'CallbackInvoke','RCX=callback,RDX=manager,actualtarget RAX'),(0x486930,'AllUpAsyncBody','RCX=capturedmanagerMonitorFlags;RDX=resolvedmanager'),(0x4869f3,'ExistingHostResult','EAX GetView2 HR;out[rbp-20]'),(0x486a50,'CreateHostResult','EAX CreateView2 HR;out[rbp-20]'),(0x486a02,'ExistingHostToggle','actualtargetRAX;RCX=host'),(0x486a86,'NewHostShow','actualtargetRAX;RCX=host,RDX=monitorManager,R8=monitor,R9D=flags'),(0x486a8b,'ShowResult','EAX Show HR'),(0x108c7c,'CreateFrames','RCX=host'),(0x108cae,'MonitorArrayResult','EAX GetMonitors HR,out[rbp+38]'),(0x108daf,'MonitorCountResult','EAX countHR;hostRDI+2e0 count'),(0x108e37,'MonitorEligibility','EAX MonitorSlot6 HR,BOOL[rbp+30],RBXmonitor'),(0x108e4c,'CreateMonitorFrameResult','EAX CreateFrameForMonitorHR'),(0x108eb0,'FramesSuccess','RDI host; frames140/148; loop can produce zeroframes')]
a=[]
for rva,n,c in points:
 chosen=[];sz=0
 for i in d.disasm(p.get_data(rva,32),rva):
  chosen.append(f'{i.address:x}: {i.mnemonic} {i.op_str}');sz+=i.size
  if sz>=12:break
 a.append({'rva':hex(rva),'name':n,'capture':c,'expected':p.get_data(rva,sz).hex(),'instructions':chosen})
obj={'physicalPCS':str(path.resolve()),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'readOnlyProposedTrace':True,'points':a};Path('work/taskview-scheduler-trace-points.json').write_text(json.dumps(obj,indent=2))
lines=[]
for start in (0x21d50,0x1d1508,0x133e94,0x486930,0x108c7c,0x1e1f70):
 f=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==start);lines.append(f'FUNCTION {start:x} '+ns.get(start,''))
 for i in d.disasm(p.get_data(start,f.EndAddress-start),start):lines.append(f'{i.address:x}: {i.mnemonic} {i.op_str}')
Path('work/taskview-scheduler-and-frames-disassembly.txt').write_text('\n'.join(lines));print('Saved',len(a),'guarded tracepoint proposals; no live processes accessed')

