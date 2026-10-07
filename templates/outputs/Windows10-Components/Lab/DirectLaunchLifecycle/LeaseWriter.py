from pathlib import Path
import os,sys,time,struct,json
target=Path(sys.argv[1]);tmp=target.with_suffix('.tmp');retries=0
Path(str(target)+'.attempt').write_text('Own atomic replacement starting')
for i in range(300):
    tmp.write_bytes(struct.pack('<QQ',i,i^0xffffffffffffffff));deadline=time.monotonic()+.25
    while True:
        try:os.replace(tmp,target);break
        except OSError as e:
            if e.winerror not in (5,32,33,303) or time.monotonic()>=deadline:raise
            retries+=1;time.sleep(.01)
    time.sleep(.002)
Path(str(target)+'.json').write_text(json.dumps({'Replacements':300,'TransientRetries':retries}),encoding='utf-8')
