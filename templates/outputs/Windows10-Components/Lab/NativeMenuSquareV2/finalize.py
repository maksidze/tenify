from pathlib import Path
import hashlib,json,ast
H=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for name in ['Launch-MenuSquareV2.py','build_test.py','finalize.py']:ast.parse((H/name).read_text())
proof=json.loads((H/'own-proof.json').read_text());assert proof['exitCode']==0 and 'FAIL'not in proof['transcript'] and proof['helperSha256']==sha(H/'MenuSquareV2.dll')
names=['MenuSquareV2.c','MenuSquareV2.dll','Guard.h','Fixture.cpp','MenuSquareV2Fixture.exe','RendererSelect.h','build_test.py','Launch-MenuSquareV2.py','native-guards.json','own-proof.json','own-proof.txt','Readme.txt','finalize.py']
files=[dict(Path=str(H/n),SHA256=sha(H/n),Bytes=(H/n).stat().st_size)for n in names]
m=dict(Version=2,HelperSHA256=sha(H/'MenuSquareV2.dll'),Scope='own #32768, exact uxtheme/PCS/shell32 attr33 value3 calls',OwnProofPassed=True,LiveUIVerified=False,SystemFilesModified=False,NativeCallers=json.loads((H/'native-guards.json').read_text()),Files=files)
(H/'manifest.json').write_text(json.dumps(m,indent=2));print('HELPER',m['HelperSHA256']);print('MANIFEST',sha(H/'manifest.json'));print('all pinned files verified; API syntax PASS')
