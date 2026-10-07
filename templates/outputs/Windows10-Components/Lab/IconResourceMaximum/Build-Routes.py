from pathlib import Path
import json,hashlib,subprocess
LAB=Path(__file__).resolve().parent
ROOT=LAB.parents[3]
PY=Path('@PYTHON_DIR@/python.exe')
ZIG=ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def wide(s):return 'L'+json.dumps(str(Path(s).resolve()),ensure_ascii=True)
manifest=json.loads((LAB/'manifest.json').read_text())
for collection in ['Mappings','ResourceOnlyMappings']:
 for entry in manifest[collection]:
  for key in ['Source','Destination']:entry[key]=str(Path(entry[key]).resolve())
(LAB/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
subprocess.run([str(PY),str(LAB/'Prepare-API.py')],check=True,stdout=subprocess.DEVNULL)
routes=[x for x in manifest['Records'] if x['Mode']!='DataOnlyMUNVFS']
assert len(routes)==20
header='#define ROUTE_COUNT 20\ntypedef struct {PCWSTR host,privatePath;const char *hostSha,*privateSha;} ROUTE;\nstatic ROUTE routes[]={\n'
for r in routes:header+='{'+wide(r['Host'])+','+wide(r['Private'])+','+json.dumps(r['HostSHA256'])+','+json.dumps(r['PrivateSHA256'])+'},\n'
header+='};\n'
fixture=LAB/'IconRouteProbe.exe';explorer=LAB.parents[1]/'Runtime/Explorer10/explorer.exe'
def cc(source,out,extra):
 subprocess.run([str(ZIG),'cc','-target','x86_64-windows-gnu','-municode','-O2',str(source),'-o',str(out),*extra],check=True)
# The own fixture is compiled first; its exact identity is pinned into the DLL.
cc(LAB/'RouteConsumer.c',LAB/'RouteConsumer.dll',['-shared','-luser32'])
fixtureHeader='typedef struct {PCWSTR host,old,privatePath;int id;} CASE;\nstatic CASE cases[]={\n'
for r in routes:
 ids=[x for x in r['ResourceGroups'] if isinstance(x,int)]
 if ids:fixtureHeader+='{'+wide(r['Host'])+','+wide(r['Old'])+','+wide(r['Private'])+','+str(ids[0])+'},\n'
fixtureHeader+='};\n#define CASE_COUNT (sizeof(cases)/sizeof(cases[0]))\n'
fixtureHeader+='#define CONSUMER_PATH '+wide(LAB/'RouteConsumer.dll')+'\n'
(LAB/'ProbeCases.h').write_text(fixtureHeader,encoding='utf-8')
cc(LAB/'IconRouteProbe.c',fixture,['-O0','-Wl,--subsystem,windows','-luser32','-lgdi32','-lshell32','-lversion'])
header+='#define FIXTURE_PATH '+wide(fixture)+'\n#define FIXTURE_SHA '+json.dumps(sha(fixture))+'\n#define EXPLORER_PATH '+wide(explorer)+'\n#define EXPLORER_SHA '+json.dumps(sha(explorer))+'\n'
(LAB/'Routes.h').write_text(header,encoding='utf-8')
cc(LAB/'IconRoutes.c',LAB/'IconRoutes.dll',['-shared','-luser32','-lshell32','-lpsapi','-lbcrypt'])
proof=dict(HelperSHA256=sha(LAB/'IconRoutes.dll'),FixtureSHA256=sha(fixture),ManifestSHA256=sha(LAB/'manifest.json'),Routes=20)
(LAB/'route-build.json').write_text(json.dumps(proof,indent=2),encoding='utf-8')
print(json.dumps(proof,indent=2))
