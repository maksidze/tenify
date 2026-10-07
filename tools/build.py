"""Assemble b013 from user-owned Windows media and authored source templates.

No live shell transition, system-directory write or package registration here.
"""
from pathlib import Path
import argparse, ctypes, hashlib, json, os, re, shutil, subprocess, sys, time

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'tools'))
sys.path.insert(0,str(REPO/'.tools/python-libs'))
from image_locale import localized_path,resource_file
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def save(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,ensure_ascii=False,indent=2),encoding='utf-8')
def under(root,relative):
    p=(root/relative).resolve()
    if not p.is_relative_to(root.resolve()):raise RuntimeError('Path escaped workspace: '+relative)
    return p
def expand(s,root,python,native=False):
    # Separate escaped-string tokens prevent generating invalid C/Python/JSON.
    pairs=[('@WORKSPACE_ESC@',str(root).replace('\\','\\\\')),('@WORKSPACE@',str(root) if native else str(root).replace('\\','/')),('@PYTHON_DIR_ESC@',str(python.parent).replace('\\','\\\\')),('@PYTHON_DIR@',str(python.parent) if native else str(python.parent).replace('\\','/'))]
    for a,b in pairs:s=s.replace(a,b)
    return s
def replace_hashes(s,mapping):
    for old,new in mapping.items():
        if old!=new:s=s.replace(old,new).replace(old.upper(),new.upper())
    # Several native adapters encode SHA256 as a C byte array.
    def bytes_array(m):
        parts=re.findall(r'0x([0-9a-fA-F]{2})',m.group(0))
        if len(parts)==32 and ''.join(parts).lower() in mapping:
            return ','.join('0x'+mapping[''.join(parts).lower()][i:i+2] for i in range(0,64,2))
        return m.group(0)
    return re.sub(r'0x[0-9a-fA-F]{2}(?:\s*,\s*0x[0-9a-fA-F]{2}){31}',bytes_array,s)

def host_check():
    win=Path(os.environ['WINDIR'])
    failures=[]
    for name,digest in read(REPO/'packaging/host-files.json').items():
        p=under(win,name)
        if not p.is_file() or sha(p)!=digest:failures.append(name)
    if failures:raise RuntimeError('Unsupported Windows11 host profile; no changes made. Mismatched files: '+', '.join(failures[:15]))
    if str(win).casefold()!='c:\\windows':raise RuntimeError('The b013 native path profile currently requires C:\\Windows')
    return win

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--workspace',required=True);ap.add_argument('--zig',required=True)
    ap.add_argument('--validate-only',action='store_true');a=ap.parse_args()
    root=Path(a.workspace).resolve();python=Path(sys.executable).resolve();zig=Path(a.zig).resolve()
    if root==REPO or root.is_relative_to(Path(os.environ['WINDIR'])):raise RuntimeError('Choose a private output directory outside Windows and outside the source repository itself.')
    win=host_check();root.mkdir(parents=True,exist_ok=True)
    marker=root/'.b013-builder-owned.json'
    if not marker.is_file() or Path(read(marker)['Workspace']).resolve()!=root:raise RuntimeError('Output is not a workspace owned by Build.ps1')
    log=root/'build-report.json';report=dict(Version='b013',StartedUtc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),Status='building',NoVFS=True,SystemFilesModified=False,LiveShellChanged=False,Steps=[])
    if not a.validate_only:(root/'READY.json').unlink(missing_ok=True)
    save(log,report)
    try:
        if a.validate_only:report['Status']='host-profile-verified';return
        image=root/'outputs/Windows10-Components/Image/4'
        provenance=read(image.parent/'media-provenance.json');language=provenance['Image']['PrimaryLanguage']
        save(root/'locale.json',dict(PrimaryLanguage=language,ImageLanguages=provenance['Image']['Languages'],Source='user-installation-image'))
        media_mapping={}
        for name,digest in read(REPO/'packaging/media-files.json').items():
            p=under(image,localized_path(name,language))
            if not p.is_file() or (not resource_file(name) and sha(p)!=digest):raise RuntimeError('Wrong/incomplete Windows10 source image: '+name)
            media_mapping[digest]=sha(p)
        report['Steps'].append('User media files verified')
        templates=read(REPO/'packaging/template-files.json');mapping=dict(media_mapping)
        shutil.copytree(REPO/'.tools/python-libs',root/'work/pylib',dirs_exist_ok=True)
        for entry in templates:
            target=under(root,entry['Path']);target.parent.mkdir(parents=True,exist_ok=True)
            s=expand((REPO/'templates'/entry['Path']).read_text(encoding='utf-8-sig'),root,python,target.suffix.lower() in ['.ps1','.bat','.ini','.txt'])
            s=s.replace('ru-RU',language)
            if target.suffix=='.json':s=json.dumps(json.loads(s),ensure_ascii=True,indent=2)
            target.write_text(s,encoding='utf-16' if target.suffix=='.ini' else 'utf-8-sig' if target.suffix.lower()=='.ps1' else 'utf-8')
            mapping[entry['OriginalSHA256']]=sha(target)
        for entry in read(REPO/'packaging/generated-guards.json'):
            source=under(image if entry['Kind']=='media' else win,entry['Source'])
            if sha(source)!=entry['SourceSHA256']:raise RuntimeError('Cannot regenerate guard from a different ABI profile')
            with source.open('rb') as f:f.seek(entry['Offset']);data=f.read(entry['Length'])
            if len(data)!=entry['Length']:raise RuntimeError('Truncated local guard source')
            target=under(root,entry['Template']);s=target.read_text(encoding='utf-8-sig')
            if entry['Token'] not in s:raise RuntimeError('Generated guard marker missing')
            target.write_text(s.replace(entry['Token'],','.join(hex(b) for b in data)),encoding='utf-8')
        for entry in templates:mapping[entry['OriginalSHA256']]=sha(under(root,entry['Path']))
        from signatures import resolve
        resolutions=[dict(Module=p['Module'],Sites=resolve(p,win)) for p in read(REPO/'packaging/signature-profiles.json')]
        save(root/'signature-report.json',dict(UniqueMatches=True,SemanticChecksPassed=True,Modules=resolutions,HostABIProfileStillRequired=True))
        lea=resolutions[1]['Sites']['LoaderLEA']
        for folder in ['SettingsNoVfsCompat','SettingsNoVfsXamlCompat']:
            p=root/'outputs/Windows10-Components/Lab'/folder/'adapter-metadata.json'
            metadata=read(p);metadata['LEA_RVA']=lea;metadata['LEABytes']=__import__('pefile').PE(str(win/'ImmersiveControlPanel/SystemSettings.exe'),fast_load=True).get_data(lea,7).hex();save(p,metadata)
        for entry in read(REPO/'packaging/copy-artifacts.json'):
            source=under(image if entry['Kind']=='media' else win,localized_path(entry['Source'],language) if entry['Kind']=='media' else entry['Source'])
            if (entry['Kind']=='host' or not resource_file(entry['Source'])) and sha(source)!=entry['SHA256']:raise RuntimeError('Source hash differs: '+entry['Source'])
            target=under(root,localized_path(entry['Output'],language));target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
            mapping[entry['SHA256']]=sha(target)
        # Resource content may legitimately differ between language images. Only
        # resource digests are refreshed; executable/ABI digests remain pinned.
        for folder in ['IconResourceMaximum']:
            p=root/'outputs/Windows10-Components/Lab'/folder/'inventory.json';inventory=read(p)
            for entry in inventory:
                if 'Old' not in entry:continue
                old=Path(entry['Old']);old=Path(localized_path(str(old),language))
                entry['Old']=str(old);entry['OldSHA256']=sha(old)
            save(p,inventory)
        import urllib.request
        for entry in read(REPO/'packaging/symbol-files.json'):
            target=under(root,entry['Output']);target.parent.mkdir(parents=True,exist_ok=True)
            if not target.exists() or sha(target)!=entry['SHA256']:
                temporary=target.with_suffix('.download')
                with urllib.request.urlopen(entry['URL'],timeout=60) as response,temporary.open('wb') as f:shutil.copyfileobj(response,f)
                if sha(temporary)!=entry['SHA256']:raise RuntimeError('Official symbol hash mismatch: '+entry['Output'])
                temporary.replace(target)
        report['Steps'].append('Private signed Windows files copied; originals preserved')
        # Historical build scripts that also activate GUI processes are deliberately
        # not called. Only these two reviewed data-only resource generators run.
        env=dict(os.environ,PYTHONPATH=str(root/'work/pylib'),ZIG_GLOBAL_CACHE_DIR=str(root/'tool-cache/zig'))
        for name in ['outputs/Windows10-Components/Lab/IconResourceMaximum/Build.py','work/build_paired_icon_containers.py','work/build_resource_compat.py']:
            p=under(root,name)
            if not p.is_file():raise RuntimeError('Required authored generator missing: '+name)
            run([str(python),str(p)],root,env,root/'build-logs'/('generate-'+p.stem+'.log'))
        report['Steps'].append('Private resource containers and resource shim generated')
        # Resolve resource digests after localized container generation, before
        # pinning them into the authored helpers. Never refresh executable pins.
        def resource_pins(x):
            if isinstance(x,dict):
                for path_key,digest_key in [('Private','PrivateSHA'),('Private','PrivateSHA256'),('Old','OldSHA256'),('Path','SHA256')]:
                    value=x.get(path_key);digest=x.get(digest_key)
                    if isinstance(value,str) and isinstance(digest,str) and resource_file(value):
                        p=Path(value)
                        if p.is_file() and p.resolve().is_relative_to(root):mapping[digest]=sha(p)
                for key,value in x.items():
                    if isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value,re.I) and resource_file(key):
                        p=Path(key)
                        if p.is_file() and p.resolve().is_relative_to(root):mapping[value]=sha(p)
                    resource_pins(value)
            elif isinstance(x,list):
                for item in x:resource_pins(item)
        for p in (root/'outputs/Windows10-Components/Lab').glob('*/manifest.json'):resource_pins(read(p))
        compiled=compile_all(root,python,zig,mapping,env)
        mapping.update(compiled)
        finalize(root,templates,mapping)
        report['Steps'].append('Authored helpers compiled; relocated integrity manifests generated')
        check=root/'outputs/Windows10-Components/Windows10-DirectOneClick.ps1'
        run([str(win/'System32/WindowsPowerShell/v1.0/powershell.exe'),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(check),'-Mode','Check'],root,env,root/'build-logs/dependency-check.log')
        report['Steps'].append('Default one-click dependency check passed')
        preflight=root/'outputs/Windows10-Components/Start-Explorer10-Direct.ps1'
        run([str(win/'System32/WindowsPowerShell/v1.0/powershell.exe'),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(preflight),'-PreflightOnly','-Profile','host-dcomp-resource','-XamlQuirk','-Icons10','-HybridTheme10'],root,env,root/'build-logs/hidden-preflight.log')
        report['Steps'].append('Hidden own Explorer folder/theme/icon preflight passed; job drained')
        report['Status']='assembled-and-preflight-verified'
        report['VisualConfirmed']=False
        save(root/'READY.json',dict(Version='b013',Status=report['Status'],Report=str(log),DefaultLauncher=str(root/'Start-Windows10.bat'),NoVFS=True,HostProfileVerified=True,MediaVerified=True,VisualConfirmed=False))
    except Exception as e:report['Status']='failed';report['Error']=str(e);raise
    finally:save(log,report)
    print(json.dumps(report,ensure_ascii=False))

def run(args,cwd,env,log):
    log.parent.mkdir(parents=True,exist_ok=True)
    with log.open('wb') as out:
        p=subprocess.run(args,cwd=cwd,env=env,stdout=out,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW,timeout=180)
    if p.returncode:raise RuntimeError('Build command failed ('+str(p.returncode)+'); see '+str(log))

def compile_all(root,python,zig,mapping,env):
    entries=read(REPO/'packaging/compile.json')
    # Identical original executables are deliberate copies; rebuilding once and
    # copying the authored result avoids ambiguous digest pins for those aliases.
    groups={}
    for e in entries:groups.setdefault(e['OriginalSHA256'],[]).append(e)
    pending=dict(groups);done={};cachepath=root/'compile-cache.json';cache=read(cachepath) if cachepath.exists() else {}
    def source_closure(p,seen=None):
        seen=set() if seen is None else seen
        if p in seen:return seen
        seen.add(p)
        if p.suffix.lower() not in ['.c','.cpp','.h','.hpp']:return seen
        text=p.read_text(encoding='utf-8-sig')
        for name in re.findall(r'^\s*#\s*include\s*"([^"]+)"',text,re.M):
            child=(p.parent/name).resolve()
            if not child.is_relative_to(root):raise RuntimeError('Include escaped generated workspace: '+str(child))
            if not child.exists():raise RuntimeError('Missing authored include: '+str(child))
            source_closure(child,seen)
        return seen
    while pending:
        progress=False
        for digest,aliases in list(pending.items()):
            e=aliases[0];sources=[under(root,s) for s in e['Sources']]
            dependencies=set()
            for s in sources:dependencies|=source_closure(s)
            texts={p:p.read_text(encoding='utf-8-sig') for p in dependencies}
            refs=set()
            for s in texts.values():
                refs.update(h.lower() for h in re.findall(r'\b[0-9a-fA-F]{64}\b',s))
                for block in re.findall(r'0x[0-9a-fA-F]{2}(?:\s*,\s*0x[0-9a-fA-F]{2}){31}',s):refs.add(''.join(re.findall(r'0x([0-9a-fA-F]{2})',block)).lower())
            blocked=(refs & set(pending))-{digest}
            if blocked:continue
            for p,s in texts.items():p.write_text(replace_hashes(s,mapping),encoding='utf-8')
            target=under(root,e['Output']);target.parent.mkdir(parents=True,exist_ok=True)
            if e['Compiler']=='csc':
                csc=Path(os.environ['WINDIR'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
                args=[str(csc),'/nologo','/target:winexe','/out:'+str(target),*e.get('Args',[]),*[str(s) for s in sources]]
            else:
                args=[str(zig),e['Compiler'],'-target','x86_64-windows-gnu',*e.get('Args',[]),*[str(s) for s in sources],'-o',str(target),*e.get('Libs',[])]
            key=hashlib.sha256(json.dumps(dict(Command=args,Sources={str(p):sha(p) for p in dependencies},ToolSHA=sha(zig)),sort_keys=True).encode()).hexdigest()
            cached=target.is_file() and cache.get(key)==sha(target)
            if not cached:
                print('Compile '+e['Output'],flush=True)
                run(args,root,env,root/'build-logs'/('compile-'+str(len(done))+'.log'))
                cache[key]=sha(target);save(cachepath,cache)
            else:print('Reuse compiled '+e['Output'],flush=True)
            new=sha(target);mapping[digest]=new;done[digest]=new
            for alias in aliases[1:]:
                path=under(root,alias['Output']);path.parent.mkdir(parents=True,exist_ok=True)
                if path!=target:shutil.copyfile(target,path)
            del pending[digest];progress=True
        if not progress:raise RuntimeError('Circular/unresolved authored binary pins: '+', '.join(g[0]['Output'] for g in pending.values()))
    return done
def finalize(root,templates,mapping):
    # Only private generated files are rehashed. Host and media digests were
    # validated before building and are never "blessed" for an unknown version.
    template_paths=[under(root,e['Path']) for e in templates]
    by_original={}
    for e in templates:by_original.setdefault(e['OriginalSHA256'],set()).add(sha(under(root,e['Path'])))
    ambiguous={h for h,values in by_original.items() if len(values)>1}
    for h in ambiguous:mapping.pop(h,None)
    hashes={e['OriginalSHA256']:sha(under(root,e['Path'])) for e in templates}
    for h in ambiguous:hashes.pop(h,None)
    mapping.update(hashes)
    for iteration in range(12):
        changed=False
        for p in template_paths:
            if not p.exists():continue
            s=p.read_text(encoding='utf-16' if p.suffix=='.ini' else 'utf-8-sig');new=replace_hashes(s,mapping)
            historical='proof' in p.name.lower() or 'evidence' in p.name.lower()
            if historical:new=s
            if p.suffix=='.json':
                try:
                    data=json.loads(new)
                    def update(x):
                        if isinstance(x,dict):
                            for name,value in list(x.items()):
                                if isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value,re.I):
                                    q=(p.parent/name).resolve()
                                    if q.is_file() and q.is_relative_to(root):x[name]=sha(q)
                            path=x.get('Path',x.get('path'))
                            if isinstance(path,str) and Path(path).is_file():
                                for key in ['SHA256','sha256']:
                                    if key in x:x[key]=sha(Path(path))
                            # Manifests with relative-name -> digest dictionaries.
                            files=x.get('Files')
                            if isinstance(files,dict):
                                for name,value in list(files.items()):
                                    if Path(name).suffix.lower() in ['.lib','.pdb']:
                                        del files[name];continue
                                    q=(p.parent/name).resolve()
                                    if isinstance(value,str) and len(value)==64 and q.is_relative_to(root) and q.is_file():files[name]=sha(q)
                            elif isinstance(files,list):
                                x['Files']=[f for f in files if not isinstance(f,dict) or Path(f.get('Path',f.get('path',''))).suffix.lower() not in ['.lib','.pdb']]
                            for v in x.values():update(v)
                        elif isinstance(x,list):
                            for v in x:update(v)
                    if historical and isinstance(data,dict):data['EvidenceScope']='Historical b013 sandbox evidence; no rebuilt-module test is implied and original evidence hashes are preserved.'
                    else:update(data)
                    new=json.dumps(data,ensure_ascii=True,indent=2)
                except ValueError:pass
            if new!=s:p.write_text(new,encoding='utf-16' if p.suffix=='.ini' else 'utf-8-sig' if p.suffix.lower()=='.ps1' else 'utf-8');changed=True
        for e in templates:
            if e['OriginalSHA256'] in ambiguous:continue
            new=sha(under(root,e['Path']))
            previous=mapping.get(e['OriginalSHA256'])
            if previous!=new:
                if previous:mapping[previous]=new
                mapping[e['OriginalSHA256']]=new;changed=True
        if not changed:break
    else:raise RuntimeError('Integrity manifest dependencies did not converge')
if __name__=='__main__':main()
