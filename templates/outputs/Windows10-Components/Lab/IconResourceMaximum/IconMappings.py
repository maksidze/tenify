"""Pure guarded mapping API; no import-time process or file mutations."""
from pathlib import Path
import hashlib,json
LAB=Path(__file__).resolve().parent
EXPECTED_MANIFEST_SHA256='7d80120c1f9f2827a6d8d5f22f5ad2cf7ab6ca2a626dd7074c09eaeb9b323bf7'
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
