from pathlib import Path
import sys
variant=sys.argv[1] if len(sys.argv)>1 else 'Baseline'
if variant not in ['Baseline','LocalPRI','FactoryWrapper']:raise ValueError(variant)
controller=Path('outputs/Windows10-Components/Probe-USVFS.py').resolve()
source=controller.read_text(encoding='utf-8-sig')
source=source.replace("out=base/'Metadata'/('usvfs-'+args.preset+'-probe.json')", "out=base/'Lab/ResourceCompat'/('"+variant+"-probe.json')")
source=source.replace("exe=base/'Runtime/Explorer10/explorer.exe'", "exe=base/'Lab/ResourceCompat/"+variant+"/explorer.exe'")
sys.argv=[str(controller),'--preset','immersive-compat','--seconds','10','--capture-debug']
exec(compile(source,str(controller),'exec'),{'__file__':str(controller)})
