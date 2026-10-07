import sys
sys.path.insert(0,'work/pylib');import pefile
p=pefile.PE('outputs/Windows10-Components/Lab/HostMultitaskingCompat/twinui.pcshell.dll');im={i.address-p.OPTIONAL_HEADER.ImageBase:(e.dll,i.name,i.ordinal) for e in p.DIRECTORY_ENTRY_IMPORT+p.DIRECTORY_ENTRY_DELAY_IMPORT for i in e.imports}
for addr in (0x485906+7+0x47f4fb,0x21e91+7+0x8e2f68,0x25a3d2+7+0x6aaa47):print(hex(addr),im.get(addr))


