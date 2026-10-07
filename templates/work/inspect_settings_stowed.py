from pathlib import Path
import argparse,re,json,bisect,sys
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'work/pylib'))
import pefile
args=argparse.ArgumentParser();args.add_argument('log');opt=args.parse_args()
log=Path(opt.log);text=log.read_text(encoding='utf-8',errors='replace');modules=[]
folder={'Windows.UI.Xaml.dll':'host-xaml','SystemSettings.dll':'old-settings-dll','SystemSettingsViewModel.Desktop.dll':'old-settings-viewmodel'}
for base,path in re.findall(r'DLL base=([0-9A-F]+) path=(.*)',text):
 path=path.removeprefix('\\\\?\\');name=path.rsplit('\\',1)[-1]
 if name not in folder:continue
 pe=pefile.PE(path,fast_load=True);symbols=json.loads((root/'work/compat-research'/folder[name]/'all-public-symbols.json').read_text());symbols.sort(key=lambda x:x['rva'])
 modules.append((int(base,16),pe.OPTIONAL_HEADER.SizeOfImage,name,symbols,[s['rva'] for s in symbols]))
output=[]
for line in text.splitlines():
 if any(k in line for k in ['STOWED index','FIRSTCHANCE_TEXT','CONTEXT']):output.append(line)
 if not ('STOWED_STACK' in line or line.startswith('STACK ')):continue
 value=int(line.rsplit('=',1)[-1],16)
 for base,size,name,ss,rv in modules:
  if not base<=value<base+size:continue
  delta=value-base;i=bisect.bisect_right(rv,delta)-1
  output.append(f"{line} {name}+{delta:x} "+(f"{ss[i]['name']}+{delta-ss[i]['rva']:x}" if i>=0 else ''))
  break
out=log.with_suffix('.symbolized.txt');out.write_text('\n'.join(output),encoding='utf-8');print(out);print('\n'.join(output[:100]))
