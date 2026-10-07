from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parent.parent
base=root/'outputs/Windows10-Components'
file=base/'Image/4/Windows/System32/AboveLockAppHost.dll'
data=file.read_bytes()
expected='7f0437223c25cb457514f0b5a98f5ac99a2a81cc'
assert len(data)==419328 and hashlib.sha1(data).hexdigest()==expected
record={'archive':'D:/sources/install.wim','index':4,
 'archivePath':'4/Windows/System32/AboveLockAppHost.dll','file':str(file),
 'size':len(data),'wimSHA1':expected,'sha256':hashlib.sha256(data).hexdigest(),
 'matchesWim':True,'embeddedAuthenticode':'NotSigned (catalog status not tested)',
 'isolatedLoadLibrary':'PASS','livePhysicalModuleConfirmed':True,
 'liveRun':'5004748f96404ff09c655b84638d75a0',
 'result':'Previous host E_NOTIMPL privileged-operations barrier passed; next failure is an unregistered old event delegate proxy.'}
out=base/'Metadata/additional-files.json'
entries=json.loads(out.read_text(encoding='utf8')) if out.exists() else []
entries=[e for e in entries if e['archivePath']!=record['archivePath']]+[record]
out.write_text(json.dumps(entries,indent=2),encoding='utf8')
print('Additional AboveLockAppHost extraction verified against WIM SHA-1 and size.')
