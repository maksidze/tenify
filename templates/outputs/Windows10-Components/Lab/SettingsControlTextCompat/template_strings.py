from pathlib import Path
import struct,json
H=Path(__file__).resolve().parent;p=H/'old-templates/077-Templates.xbf';b=p.read_bytes();v=struct.unpack_from('<I',b,16)[0];offsets=struct.unpack_from('<6Q',b,20);a=12+offsets[0];n=struct.unpack_from('<I',b,a)[0];a+=4;strings=[]
for _ in range(n):
 length=struct.unpack_from('<I',b,a)[0];a+=4;strings.append(b[a:a+2*length].decode('utf-16-le'));a+=length*2+(2 if v>=1 else 0)
(H/'template-strings.json').write_text(json.dumps(strings,ensure_ascii=False,indent=2),encoding='utf-8')
print('\n'.join(str(i)+' '+s for i,s in enumerate(strings) if any(t.lower() in s.lower() for t in ['Description','ResourceLoader','DisplayName','Dynamic','BooleanSettingTemplate'])))
