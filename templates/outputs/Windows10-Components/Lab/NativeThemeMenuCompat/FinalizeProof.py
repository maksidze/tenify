from pathlib import Path
import json,hashlib
LAB=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((LAB/'manifest.json').read_text());unit=json.loads((LAB/'unit-proof.json').read_text());popupPath=LAB.parent/'NativeMenuThemeColorCompat/real-helper-proof.json';popup=json.loads(popupPath.read_text())
assert unit['Pass'] and unit['Files']['ThemeMenu.cpp']==sha(LAB/'ThemeMenu.cpp')
assert popup['HelperSHA']==sha(LAB/'ThemeMenuCompat.dll')
assert sorted(r['Policy']for r in popup['Results'])==[2,3]
assert all(r['Exit']==0 and 'real helper initialized PASS' in r['Report'] and 'real helper restored PASS' in r['Report'] and 'desktop close PASS' in r['Report'] and 'FAIL' not in r['Report'] for r in popup['Results'])
for name,pin in manifest['Files'].items():assert sha(LAB/name)==pin,name
for p,pin in manifest['Dependencies'].items():assert sha(Path(p))==pin,p
proof=dict(Pass=True,ProductionLiveTested=False,HelperSHA=sha(LAB/'ThemeMenuCompat.dll'),SourceSHA=sha(LAB/'ThemeMenu.cpp'),UnitClassifier=unit,ActualPopup=popup,ActualPopupFile=str(popupPath))
(LAB/'own-proof.json').write_text(json.dumps(proof,indent=2))
for name in ['Readme.txt','UnitFixture.cpp','UnitFixture.exe','UnitTest.py','unit-proof.json','own-proof.json','FinalizeProof.py','contract.json']:
 manifest['Files'][name]=sha(LAB/name)
manifest['OwnProofPassed']=True
(LAB/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps(dict(Ready=True,HelperSHA=proof['HelperSHA'],ManifestSHA=sha(LAB/'manifest.json'))))
