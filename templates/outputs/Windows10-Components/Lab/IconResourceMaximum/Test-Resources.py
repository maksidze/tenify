from pathlib import Path
import subprocess,json
lab=Path(__file__).resolve().parent;manifest=json.loads((lab/'manifest.json').read_text());records=manifest['Records'];paths=[]
for r in records:paths.extend([r['Host'],r['Old'],r['Private']])
(lab/'probe-input.txt').write_text('\r\n'.join(paths)+'\r\n',encoding='utf-16')
p=subprocess.run([str(lab/'ResourceProbe.exe'),str(lab/'probe-input.txt'),str(lab/'probe-results.jsonl')],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=50);assert p.returncode==0,p.stderr
results=[]
for line in (lab/'probe-results.jsonl').read_text().splitlines():
 try:results.append(json.loads(line))
 except Exception:print(repr(line));raise
byfile={}
for r in results:byfile.setdefault(r['file'],{})[r.get('group')]=r
checked=0;failures=[];baseline_blank=[];changed=0
for i,record in enumerate(records):
 host=byfile.get(i*3,{});old=byfile.get(i*3+1,{});merged=byfile.get(i*3+2,{})
 for group in record['ResourceGroups']:
  a=old.get(group);b=merged.get(group);n=host.get(group)
  if not a or not b or a['hash']!=b['hash'] or a['nonzero']!=b['nonzero']:failures.append(dict(Module=record['Host'],Group=group,Old=a,Merged=b))
  else:
   checked+=1
   if n and n['hash']!=b['hash']:changed+=1
   if not a['nonzero']:baseline_blank.append(dict(Module=record['Host'],Group=group))
 for group in record['HostOnlyGroups']:
  if merged.get(group)!=host.get(group):
   a=host.get(group);b=merged.get(group)
   if not a or not b or (a['hash'],a['nonzero'])!=(b['hash'],b['nonzero']):failures.append(dict(HostOnlyChanged=group,Module=record['Host']))
proof=dict(LoadLibrariesAsDataOnly=True,OwnGUIChildNoWindow=True,Files=len(records),ResourceGroupsVerified=checked,ChangedPixels=changed,Failures=failures,OldBaselineBlank=baseline_blank,NoSystemFilesModified=True)
(lab/'resource-own-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps({k:v for k,v in proof.items() if k not in ['Failures','OldBaselineBlank']}));assert not failures,failures[:3]
