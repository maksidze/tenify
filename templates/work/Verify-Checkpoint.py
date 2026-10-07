import sys,json,hashlib,datetime,os
from pathlib import Path
build=Path(sys.argv[1]).resolve()
m=json.loads((build/'manifest.json').read_text(encoding='utf8'))
def sha(p):
 p=Path('\\\\?\\'+str(p.resolve())) if os.name=='nt' else p
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
checks=[]
for rel,h in m.get('buildFiles',{}).items():checks.append((build/rel,h,'build-entrypoint'))
for rel,h in m['files'].items():
 checks.extend([(build/rel,h,'snapshot'),(Path(m['originalWorkspace'])/rel,h,'source')])
for label,d in m['externalDependencies'].items():
 if not d['files']:raise SystemExit('Empty dependency '+label)
 root=Path(d['path'])
 for rel,h in d['files'].items():checks.append((root/rel if root.is_dir() else root,h,label))
for p,h in m['hostRequirements'].items():checks.append((Path(p),h,'host'))
fail=[]
for p,h,label in checks:
 if sha(p)!=h:fail.append({'path':str(p),'kind':label})
result={'checkedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'build':str(build),'checks':len(checks),'snapshotFiles':len(m['files']),'snapshotBytes':sum((Path('\\\\?\\'+str(build/rel)) if os.name=='nt' else build/rel).stat().st_size for rel in m['files']),'failures':fail,'UIActions':False,'RestoreApplied':False}
(build/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps(result,ensure_ascii=False))
if fail:raise SystemExit(1)
