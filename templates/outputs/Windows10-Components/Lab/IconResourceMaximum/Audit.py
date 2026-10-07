from pathlib import Path
import sys,json,hashlib,struct,io
lab=Path(__file__).resolve().parent;sys.path.insert(0,str(lab.parents[3]/'work/pylib'))
from Inventory import icons
from PIL import Image,ImageDraw
def payload(r,g):
 k=next(k for k in r if k[0]==14 and k[1]==g);data=r[k];n=struct.unpack_from('<H',data,4)[0];header=struct.pack('<HHH',0,1,n);entries=bytearray();content=bytearray();offset=6+n*16
 for i in range(n):
  e=data[6+i*14:6+(i+1)*14];idx=struct.unpack_from('<H',e,12)[0];key=next((k for k in r if k==(3,idx,k[2])),None) if False else next(k for k in r if k[0]==3 and k[1]==idx)
  b=r.get((3,idx,k[2]),r[key]);entries.extend(e[:8]+struct.pack('<II',len(b),offset+len(content)));content.extend(b)
 return header+entries+content
def render(r,g):
 image=Image.open(io.BytesIO(payload(r,g)))
 if hasattr(image,'ico'):image=image.ico.getimage((32,32))
 return image.convert('RGBA').resize((32,32),Image.Resampling.LANCZOS)
records=json.loads((lab/'inventory.json').read_text());changed=[];stable=[];failed=[]
for rec in records:
 if rec.get('HostMissing'):continue
 old=icons(Path(rec['Old']));host=icons(Path(rec['Host']))
 for g in rec['CommonGroups']:
  try:
   a=render(old,g);b=render(host,g);same=a.tobytes()==b.tobytes()
   item=dict(Relative=rec['Relative'],Group=g,SamePixels=same,OldPixelSHA256=hashlib.sha256(a.tobytes()).hexdigest(),HostPixelSHA256=hashlib.sha256(b.tobytes()).hexdigest())
   if same:stable.append(item)
   else:changed.append((item,a,b))
  except Exception as e:failed.append(dict(Relative=rec['Relative'],Group=g,Error=str(e)))
pages=[]
for page in range((len(changed)+119)//120):
 subset=changed[page*120:(page+1)*120];canvas=Image.new('RGB',(1200,((len(subset)+3)//4)*58),(235,235,235));draw=ImageDraw.Draw(canvas)
 for i,(item,a,b) in enumerate(subset):
  x=(i%4)*300;y=(i//4)*58;label=item['Relative'].split('\\')[-1];draw.text((x+2,y+2),str(page*120+i)+' '+label[:28]+' #'+str(item['Group']),fill='black');canvas.paste(a,(x+6,y+19),a);canvas.paste(b,(x+54,y+19),b);draw.text((x+98,y+24),'10 / 11',fill='black')
 p=lab/('changed-pairs-'+str(page)+'.png');canvas.save(p);pages.append(str(p))
(lab/'group-audit.json').write_text(json.dumps(dict(StablePixels=stable,Changed=[i for i,_,_ in changed],Failed=failed,Pages=pages),indent=2));print(json.dumps(dict(Stable=len(stable),Changed=len(changed),Failed=len(failed),Pages=pages)))
