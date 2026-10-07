from pathlib import Path
import sys
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
p=pefile.PE('outputs/Windows10-Components/Lab/PfnCompat/W1N32U.dll')
for s in p.sections:print(s.Name,s.VirtualAddress,s.Misc_VirtualSize,s.SizeOfRawData)
