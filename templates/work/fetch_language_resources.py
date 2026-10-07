import urllib.request,struct,pathlib,json
URL='https://software-download.microsoft.com/download/pr/19041.1.191206-1406.vb_release_CLIENTLANGPACKDVD_OEM_MULTI.iso'
def fetch(start,size):
 requestsize=max(size,2048)
 req=urllib.request.Request(URL,headers={'Range':f'bytes={start}-{start+requestsize-1}'})
 with urllib.request.urlopen(req,timeout=60) as r:
  if r.status!=206:raise RuntimeError('Range requests unavailable')
  d=r.read()
  if len(d)!=requestsize:raise RuntimeError('Short response')
  return d[:size]
def record(d):
 n=d[32];return {'sector':struct.unpack_from('<I',d,2)[0],'size':struct.unpack_from('<I',d,10)[0],'directory':bool(d[25]&2),'name':d[33:33+n]}
desc=fetch(16*2048,16*2048);joliet=False;root=None
for i in range(0,len(desc),2048):
 d=desc[i:i+2048]
 if d[:1]==b'\x01':root=record(d[156:])
 if d[:1]==b'\x02' and d[88:91] in [b'%/@',b'%/C',b'%/E']:root=record(d[156:]);joliet=True;break
def entries(r):
 data=fetch(r['sector']*2048,r['size']);out=[];p=0
 while p<len(data):
  n=data[p]
  if not n:p=((p//2048)+1)*2048;continue
  item=record(data[p:p+n]);p+=n
  if item['name'] in [b'\0',b'\1']:continue
  item['name']=item['name'].decode('utf-16-be' if joliet else 'ascii').split(';')[0];out.append(item)
 return out
def walk(r,prefix='',depth=0):
 for e in entries(r):
  name=prefix+'/'+e['name'];print(name,e['size'],flush=True)
  if e['directory'] and depth<3 and (depth==0 or 'x64' in name.lower() or 'amd64' in name.lower()):walk(e,name,depth+1)
  elif not e['directory'] and ('x64' in name.lower() or 'amd64' in name.lower()) and ('ru-ru' in name.lower() or 'en-us' in name.lower()) and name.lower().endswith('.cab'):
   path=pathlib.Path('work')/e['name'];path.write_bytes(fetch(e['sector']*2048,e['size']));print('DOWNLOADED',path,flush=True)
print('ROOT',root,flush=True);walk(root)
