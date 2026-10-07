from pathlib import Path
import json,sys,hashlib,struct
sys.path.insert(0,'work/pylib');import pefile,capstone
base=Path('outputs/Windows10-Components');exe=base/'Runtime/Explorer10/explorer.exe';pcs=base/'Lab/HostMultitaskingCompat/twinui.pcshell.dll';d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
def guard(path,rva):
 p=pefile.PE(str(path));instructions=list(d.disasm(p.get_data(rva,32),rva));chosen=[];size=0
 for i in instructions:
  chosen.append({'rva':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str});size+=i.size
  if size>=12:break
 return {'rva':hex(rva),'expected':p.get_data(rva,size).hex(),'instructions':chosen}
points=[(0x233990,'buttonEntry','RCX=this; EDX=ClickDevice; [this+8] buttonHWND'),(0x2339df,'monitorPropertyResult','RAX=TaskbarMonitor HMONITOR'),(0x2339fb,'shellServiceProviderResult','EAX=GetImmersiveShellServiceProvider HRESULT'),(0x233699,'queueCall','ECX=3; R8D=originThreadId; [rsp+20]=task'),(0x2336a5,'queueResult','EAX=SHTaskPoolQueueTask HRESULT (caller v_OnClick discards it)'),(0x2336d0,'workerEntry','RCX=capture; +0ClickDevice,+8HMONITOR,+10ServiceProvider,+18buttonBool'),(0x23371b,'queryServiceResult','EAX=QueryService HRESULT; out=[rsp+40]'),(0x23374d,'toggleCall','RCX=IAllUpViewInvoker;RDX=HMONITOR;R8D=flags'),(0x233753,'toggleResult','EAX=ToggleAllUpView HRESULT')]
obj={'scope':'Read-only trace configuration; do not apply automatically','oldExe':str(exe.resolve()),'oldExeSha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'nativePrivatePCS':str(pcs.resolve()),'nativePrivatePCSSha256':hashlib.sha256(pcs.read_bytes()).hexdigest(),'oldPoints':[{**guard(exe,a),'name':n,'capture':c} for a,n,c in points],'nativePoints':[guard(pcs,a) for a in (0x486b90,0x486d50,0x486db0,0x486e34,0x486eb7,0x486f03)],'abi':{'iid':'e053969d-e07d-482d-ae3b-17d1f01bf1ad','interface':'IAllUpViewInvoker','oldVtableRva':'0x5303a0','nativeVtableRva':'0x700ff8','methodSlot':3,'oldMethodRva':'0x3f33a0','nativeMethodRva':'0x486d50','signature':'HRESULT ToggleAllUpView(HMONITOR,ALL_UP_VIEW_FLAGS)','unchanged':True}}
json.dump(obj,open('work/taskview-button-trace-points.json','w'),indent=2);print(obj['oldExeSha256'],obj['nativePrivatePCSSha256']);print('guard points',len(obj['oldPoints']))
