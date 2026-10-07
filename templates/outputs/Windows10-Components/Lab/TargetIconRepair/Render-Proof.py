from pathlib import Path
import json
from PIL import Image,ImageDraw
LAB=Path(__file__).resolve().parent
active=json.loads((LAB/'active.json').read_text());journal=json.loads((Path(active['Directory'])/'journal.json').read_text());folder=Path(journal['Thumbnail']['Output']);report=json.loads((folder/'icons.json').read_text());rows={r['name']:r for r in report['icons']}
names=['nonempty-fileinfo-100','nonempty-factory-4','nonempty-factory-8','own-force-thumbnail','after-force-factory-8']
out=Image.new('RGB',(len(names)*190,155),'#dedede');draw=ImageDraw.Draw(out)
for i,n in enumerate(names):
 r=rows[n];image=Image.frombytes('RGBA',(r['width'],r['height']),(folder/(n+'.bgra')).read_bytes(),'raw','BGRA')
 draw.text((i*190+5,5),n,fill='black');out.paste(image,(i*190+20,40),image if image.getextrema()[3][1]else None)
out.save(LAB/'wub-own-api-proof.png')
