"""Selective extraction from user's mounted install.wim/install.esd; no OS mount."""
from pathlib import Path
import argparse,json,os,re,shutil,subprocess,xml.etree.ElementTree as ET
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from image_locale import image_languages,localized_path
def main():
 p=argparse.ArgumentParser();p.add_argument('--media',required=True);p.add_argument('--index',type=int,default=0);p.add_argument('--sevenzip',required=True);p.add_argument('--destination',required=True);p.add_argument('--list',required=True);a=p.parse_args()
 media=Path(a.media).resolve();dest=Path(a.destination).resolve();win=Path(os.environ['WINDIR']).resolve()
 if dest==win or dest.is_relative_to(win):raise RuntimeError('Extraction into Windows is forbidden')
 if media.is_file() and media.suffix.lower() in ['.wim','.esd']:archive=media
 else:
  candidates=[media/'sources/install.wim',media/'sources/install.esd'];archive=next((p for p in candidates if p.is_file()),None)
  if archive is None:raise RuntimeError('No sources/install.wim or install.esd under mounted media path')
 def command(args,**kw):return subprocess.run([a.sevenzip,*args],creationflags=subprocess.CREATE_NO_WINDOW,**kw)
 xml=command(['x',str(archive),'[1].xml','-so'],capture_output=True,timeout=60)
 if xml.returncode not in [0,1]:raise RuntimeError('Cannot read WIM image metadata: '+xml.stderr.decode(errors='replace'))
 tree=ET.fromstring(xml.stdout);images=[]
 for e in tree.findall('IMAGE'):
  w=e.find('WINDOWS');primary,languages=image_languages(w)
  version='.'.join(w.findtext('VERSION/'+k,'') for k in ['MAJOR','MINOR','BUILD','SPBUILD'])
  images.append(dict(Index=int(e.attrib['INDEX']),Name=e.findtext('NAME'),Edition=w.findtext('EDITIONID'),Arch=w.findtext('ARCH'),Languages=languages,PrimaryLanguage=primary,Version=version))
 candidates=[i for i in images if i['Edition']=='Professional' and i['Arch']=='9' and i['Version']=='10.0.19045.5487' and (not a.index or i['Index']==a.index)]
 if len(candidates)!=1:raise RuntimeError('Supported baseline is Windows10 Pro AMD64 19045.5487. Available images: '+json.dumps(images,ensure_ascii=False))
 selected=candidates[0];index=selected['Index'];names=[localized_path(n,selected['PrimaryLanguage']) for n in Path(a.list).read_text(encoding='utf-8-sig').splitlines()]
 for name in names:
  if not name or name.startswith(('/', '\\')) or any(x in name.replace('\\','/').split('/') for x in ['..','.']) or re.search(r'[:*?<>|\x00-\x1f]',name):raise RuntimeError('Unsafe extraction-list entry: '+repr(name))
  if not (dest/'4'/name).resolve().is_relative_to(dest):raise RuntimeError('Extraction list escaped private destination')
 dest.mkdir(parents=True,exist_ok=True);listing=dest/'extract-list.txt';listing.write_text('\n'.join(str(index)+'/'+n.replace('\\','/') for n in names)+'\n',encoding='utf-8')
 log=dest/'extraction.log'
 with log.open('wb') as f:
  result=command(['x',str(archive),'@'+str(listing),'-scsUTF-8','-spd','-o'+str(dest),'-y'],stdout=f,stderr=subprocess.STDOUT,timeout=900)
 if result.returncode not in [0,1]:raise RuntimeError('Selective extraction failed; see '+str(log))
 # b013's internal Image/4 layout is independent of the actual ISO edition index.
 if index!=4:
  for name in names:
   src=dest/str(index)/name;target=dest/'4'/name;target.parent.mkdir(parents=True,exist_ok=True)
   if not src.is_file() or src.is_symlink():raise RuntimeError('Missing/linked extracted source: '+name)
   shutil.copyfile(src,target)
 for name in names:
  f=dest/'4'/name
  if not f.is_file() or f.is_symlink() or not f.resolve().is_relative_to(dest):raise RuntimeError('Extracted file failed containment check: '+name)
 (dest/'media-provenance.json').write_text(json.dumps(dict(Archive=str(archive),Image=selected,RequestedFiles=len(names),SevenZipExitCode=result.returncode,HashesMustBeVerifiedBeforeBuild=True),ensure_ascii=False,indent=2),encoding='utf-8')
 print('User media extracted: '+str(len(names))+' files; index '+str(index))
if __name__=='__main__':main()
