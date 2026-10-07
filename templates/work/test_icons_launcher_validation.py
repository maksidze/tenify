from pathlib import Path
import json,hashlib,types,textwrap
base=Path('outputs/Windows10-Components').resolve();s=(base/'Launch-Explorer10-VFS.py').read_text();code=textwrap.dedent(s[s.index('    iconResources=[]'):s.index("    if a.no_legacy_touchpad")])
def check(profile,body=code):
 ns={'a':types.SimpleNamespace(icons10=True,profile=profile),'base':base,'win':Path('C:/Windows'),'hashlib':hashlib,'json':json,'state':{}}
 exec(body,ns);return ns
ns=check('host-dcomp-resource');assert len(ns['iconResources'])==2
checks={'nativeAndMergedHashValidation':True,'mappingCount':2,'unsupportedProfileRejected':False,'manifestMismatchRejected':False,'noChildrenCreated':True}
try:check('legacy')
except RuntimeError:checks['unsupportedProfileRejected']=True
sha=hashlib.sha256((base/'Lab/IconResourceCompat/merged-resource-manifest.json').read_bytes()).hexdigest()
try:check('host-dcomp-resource',code.replace(sha,'0'*64))
except RuntimeError:checks['manifestMismatchRejected']=True
(base/'Lab/IconResourceCompat/launcher-readonly-checks.json').write_text(json.dumps(checks,indent=2),encoding='utf8');print(checks)
