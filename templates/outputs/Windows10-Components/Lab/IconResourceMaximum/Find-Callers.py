from pathlib import Path
import sys,struct,json,bisect
lab=Path(__file__).resolve().parent;root=lab.parents[3];sys.path.insert(0,str(root/'work/pylib'))
import pefile,capstone
targets={51380:'QuickAccess/Home',16770:'Sharing',16752:'FolderShortcut/Recent',16771:'Recent/Check',5369:'UserRestriction',1010:'Sharing',97:'Delete/Archive',31:'Unknown/Archive'}
results=[]
for mod,syms in [('shell32.dll','host-shell32'),('ExplorerFrame.dll','host-explorerframe')]:
 p=pefile.PE('C:/Windows/System32/'+mod);symbols=json.loads((root/'work/compat-research'/syms/'all-public-symbols.json').read_text());symbols.sort(key=lambda s:s['rva']);starts=[s['rva'] for s in symbols]
 section=next(s for s in p.sections if s.Name.rstrip(b'\0')==b'.text');blob=section.get_data();cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 for value in targets:
  needle=struct.pack('<I',value);pos=0
  while True:
   at=blob.find(needle,pos)
   if at<0:break
   pos=at+1
   for start in range(max(0,at-12),at):
    instructions=list(cs.disasm(blob[start:at+4],section.VirtualAddress+start))
    if not instructions:continue
    i=instructions[-1]
    if i.address+i.size!=section.VirtualAddress+at+4 or not any(o.type==capstone.x86.X86_OP_IMM and o.imm==value for o in i.operands):continue
    idx=bisect.bisect_right(starts,i.address)-1
    fn=next((f.struct for f in p.DIRECTORY_ENTRY_EXCEPTION if f.struct.BeginAddress<=i.address<f.struct.EndAddress),None)
    if fn and i.address>=fn.BeginAddress:results.append(dict(Module=mod,Id=value,Rva=hex(i.address),Instruction=i.mnemonic+' '+i.op_str,NearestSymbol=symbols[idx]['name'] if idx>=0 else '?',FunctionStart=hex(fn.BeginAddress)));break
(lab/'caller-evidence.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
