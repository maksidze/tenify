from pathlib import Path
import json,sys
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'))
from PIL import Image,ImageDraw
lab=root/'outputs/Windows10-Components/Lab/IconResourceCompat';d=json.loads((lab/'own-resource-icon-probe.json').read_text());run=Path(d['run'])
rows=d['results']['native']['icons'];im=Image.new('RGB',(760,110*9),(245,245,245));draw=ImageDraw.Draw(im)
for i,row in enumerate(rows):
 x=(i%4)*190;y=(i//4)*110;draw.text((x+4,y+2),'Stock ID '+str(row['id']),fill=(20,20,20))
 for j,preset in enumerate(['native','merged-resource-overlay']):
  p=run/preset/('stock-'+str(row['id'])+'.bgra')
  if not p.exists():continue
  icon=Image.frombytes('RGBA',(32,32),p.read_bytes(),'raw','BGRA');im.paste(icon,(x+15+80*j,y+27),icon)
  draw.text((x+4+80*j,y+69),'Win11' if j==0 else 'Win10',fill=(20,20,20))
im.save(lab/'stock-icons-comparison.png')
