"""Private, hash-verified wheels from PyPI; never installs globally."""
from pathlib import Path
import hashlib,json,sys,urllib.request,zipfile
repo=Path(__file__).resolve().parents[1];dest=repo/'.tools/python-libs';dest.mkdir(parents=True,exist_ok=True)
lock={}
for name,version in [('pefile','2024.8.26'),('capstone','5.0.9'),('keystone-engine','0.9.2')]:
    meta=json.load(urllib.request.urlopen(f'https://pypi.org/pypi/{name}/{version}/json',timeout=30))
    wheels=[f for f in meta['urls'] if f['filename'].endswith('.whl') and ('win_amd64' in f['filename'] or 'none-any' in f['filename']) and ('cp3' not in f['filename'] or 'cp312' in f['filename'])]
    if len(wheels)!=1:raise RuntimeError('Ambiguous compatible wheel: '+name)
    item=wheels[0];archive=repo/'.tools'/item['filename'];expected=item['digests']['sha256']
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:
        with urllib.request.urlopen(item['url'],timeout=60) as response:archive.write_bytes(response.read())
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:raise RuntimeError('Wheel SHA256 differs: '+name)
    with zipfile.ZipFile(archive) as z:
        for f in z.infolist():
            if not (dest/f.filename).resolve().is_relative_to(dest.resolve()):raise RuntimeError('Unsafe wheel path')
        z.extractall(dest)
    lock[name]=dict(Version=version,File=item['filename'],SHA256=expected,URL=item['url'],License=meta['info'].get('license'))
(repo/'.tools/python-package-lock.json').write_text(json.dumps(lock,indent=2),encoding='utf-8')
# The embeddable interpreter's _pth safe-path mode omits the launched script's
# directory. Restore normal script-local imports only in this private interpreter.
(dest/'sitecustomize.py').write_text("import sys\nfrom pathlib import Path\nif sys.argv and sys.argv[0] not in ('-c','-m','-',''):\n p=Path(sys.argv[0]).resolve()\n if p.is_file():sys.path.insert(0,str(p.parent))\n",encoding='utf-8')
print('Private Python packages ready')
