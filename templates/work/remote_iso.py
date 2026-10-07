import sys,io,urllib.request,pathlib
sys.path.insert(0,'work/pylib')
import pycdlib
URL='https://software-download.microsoft.com/download/pr/19041.1.191206-1406.vb_release_CLIENTLANGPACKDVD_OEM_MULTI.iso'
class Remote(io.RawIOBase):
 def __init__(self):self.pos=0;self.length=5950959616;self.blocks={};self.blocksize=4*1024*1024
 def seekable(self):return True
 def readable(self):return True
 def tell(self):return self.pos
 def seek(self,offset,whence=0):
  self.pos=offset if whence==0 else self.pos+offset if whence==1 else self.length+offset
  return self.pos
 def read(self,size=-1):
  if size<0:raise RuntimeError('Refusing full image download')
  end=min(self.pos+size,self.length);parts=[]
  while self.pos<end:
   number=self.pos//self.blocksize;start=number*self.blocksize;stop=min(start+self.blocksize,self.length)
   if number not in self.blocks:
    req=urllib.request.Request(URL,headers={'Range':f'bytes={start}-{stop-1}'})
    with urllib.request.urlopen(req,timeout=45) as r:
     if r.status!=206:raise RuntimeError('Range unsupported')
     d=r.read()
    if len(d)!=stop-start:raise RuntimeError('Incorrect range size')
    self.blocks[number]=d
   chunk=self.blocks[number][self.pos-start:min(end,stop)-start];parts.append(chunk);self.pos+=len(chunk)
  return b''.join(parts)
remote=Remote();iso=pycdlib.PyCdlib();iso.open_fp(remote)
for name in ['Microsoft-Windows-Client-Language-Pack_x64_ru-ru.cab','Microsoft-Windows-Client-Language-Pack_x64_en-us.cab']:
 path='/x64/langpacks/'+name;dest=pathlib.Path('work')/name
 print('EXTRACTING',path,flush=True)
 iso.get_file_from_iso(local_path=str(dest),udf_path=path);print('EXTRACTED',str(dest),dest.stat().st_size,flush=True)
iso.close()
