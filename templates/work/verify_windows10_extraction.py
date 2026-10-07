from pathlib import Path
import json,hashlib,shutil,collections
base=Path('outputs/Windows10-Components');root=Path('\\\\?\\'+str((base/'Image').resolve()))
s=json.loads((base/'Metadata/selection.json').read_text(encoding='utf-8'))
bysha=collections.defaultdict(list)
for x in s:
 if x.get('wimSHA1'):bysha[x['wimSHA1']].append(x)
recovered=[];missing=[];mismatch=[];verified=0
for x in s:
 p=root/x['archivePath']
 if not p.is_file():
  source=next((root/y['archivePath'] for y in bysha[x.get('wimSHA1')] if (root/y['archivePath']).is_file()),None)
  if source and hashlib.sha1(source.read_bytes()).hexdigest()==x['wimSHA1']:
   p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,p);recovered.append({'path':x['path'],'source':str(source),'reason':'Same WIM SHA1 and verified content'})
  else:missing.append(x)
 if p.is_file():
  data=p.read_bytes()
  if len(data)!=x['size'] or (x.get('wimSHA1') and hashlib.sha1(data).hexdigest()!=x['wimSHA1']):mismatch.append(x['path'])
  else:verified+=1
report={'selectedFiles':len(s),'verifiedFiles':verified,'missing':missing,'mismatches':mismatch,'recoveredSameContent':recovered,'archiveWarning':'7-Zip reported incorrect reference count; individual file length and WIM SHA1 are verified'}
(base/'Metadata/extraction-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({k:len(v) if isinstance(v,list) else v for k,v in report.items()},indent=2))
if missing:
 targets={x['archivePath'] for x in missing};record={};links=[]
 with Path('work/windows10-wim-list.txt').open(encoding='utf-8-sig',errors='replace') as f:
  for line in f:
   line=line.rstrip('\r\n')
   if not line:
    if record.get('Path') in targets:
     links.append(record)
    record={}
   elif ' = ' in line:k,v=line.split(' = ',1);record[k]=v
 (base/'Metadata/missing-wim-records.json').write_text(json.dumps(links,indent=2),encoding='utf-8')
 print('Missing record sample:',links[:2])
