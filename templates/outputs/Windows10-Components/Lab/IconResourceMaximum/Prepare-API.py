from pathlib import Path
import hashlib,json
lab=Path(__file__).resolve().parent
digest=hashlib.sha256((lab/'manifest.json').read_bytes()).hexdigest()
source='''"""Pure guarded mapping API; no import-time process or file mutations."""
from pathlib import Path
import hashlib,json
LAB=Path(__file__).resolve().parent
EXPECTED_MANIFEST_SHA256='''+repr(digest)+'''
def get_icon_mappings():
    path=LAB/'manifest.json'
    if hashlib.sha256(path.read_bytes()).hexdigest()!=EXPECTED_MANIFEST_SHA256:raise RuntimeError('Icon manifest changed.')
    manifest=json.loads(path.read_text())
    for record in manifest['Records']:
        for field,digest in [('Host','HostSHA256'),('Old','OldSHA256'),('Private','PrivateSHA256')]:
            if hashlib.sha256(Path(record[field]).read_bytes()).hexdigest()!=record[digest]:raise RuntimeError('Icon resource hash differs: '+record[field])
    return manifest['Mappings']
def get_resource_only_routes():
    get_icon_mappings()
    return json.loads((LAB/'manifest.json').read_text())['ResourceOnlyMappings']
if __name__=='__main__':print(json.dumps(get_icon_mappings(),indent=2))
'''
(lab/'IconMappings.py').write_text(source,encoding='utf-8')
proof=json.loads((lab/'resource-own-proof.json').read_text());registry=json.loads((lab/'registry-icon-evidence.json').read_text());stock=json.loads((lab/'own-resource-icon-probe.json').read_text())
manifest=json.loads((lab/'manifest.json').read_text());index=next(i for i,x in enumerate(manifest['Records']) if x['Host'].lower().endswith('explorerframe.dll.mun'));rows=[json.loads(line) for line in (lab/'probe-results.jsonl').read_text().splitlines()]
skipped=[x for x in rows if x['file'] in (index*3,index*3+1,index*3+2) and x.get('group')==101]
summary=dict(ManifestSHA256=digest,Files=len(manifest['Records']),DataOnlyMUNMappings=len(manifest['Mappings']),ResourceOnlyContainerRoutes=len(manifest['ResourceOnlyMappings']),Groups=proof['ResourceGroupsVerified'],WindowsRenderedChanged=proof['ChangedPixels'],StockQueries=len(stock['comparisons']),StockChanged=sum(x['pixelChanged'] for x in stock['comparisons']),NewBlankRegressions=stock['newBlankRegressions'],RegistryExactIconContracts=sum(x['SameResourceContract'] for x in registry),SkippedExplorerFrame101NativeProbe=skipped,CodeDLLsOverlaid=False,OldBaselineBlankCount=len(proof['OldBaselineBlank']),UIActivation=False)
(lab/'ready-proof.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))
