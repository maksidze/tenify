from pathlib import Path
import subprocess,json,hashlib
X=Path(__file__).resolve().parent;z=X.parents[3]/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
libs=['-lole32','-lapi-ms-win-core-winrt-l1-1-0','-lapi-ms-win-core-winrt-string-l1-1-0','-lshell32','-luser32','-lbcrypt','-lpsapi','-luuid']
p=subprocess.run([str(z),'c++','-target','x86_64-windows-gnu','-O2','-std=c++17',str(X/'SettingsFactorySelectorXaml.cpp'),'-o',str(X/'SettingsFactorySelectorXaml.dll'),'-shared',*libs],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=60);(X/'build.log').write_bytes(p.stdout+p.stderr)
if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();m=json.loads((X/'adapter-metadata.json').read_text());m['SelectorSHA256']=sha(m['Selector']);m['Files']=[dict(Path=x['Path'],SHA256=sha(x['Path'])) for x in m['Files']];(X/'adapter-metadata.json').write_text(json.dumps(m,indent=2));(X/'manifest.json').write_text(json.dumps(dict(NoVFS=True,ScopedNativeXamlOldFactories=True,Files=m['Files']+[dict(Path=str(X/'adapter-metadata.json'),SHA256=sha(X/'adapter-metadata.json'))]),indent=2))
