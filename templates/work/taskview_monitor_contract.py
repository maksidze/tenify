import sys,json,uuid
sys.path.insert(0,'work/pylib');import pefile
p=pefile.PE('outputs/Windows10-Components/Lab/HostMultitaskingCompat/twinui.pcshell.dll')
print('STATICS IID',uuid.UUID(bytes_le=p.get_data(0x20fc60+7+0x556f91,16)))
for r in json.load(open('work/compat-research/host-udkshellcommon/all-public-symbols.json')):
 if ('DisplayMonitorInfoCollection' in r['name'] or 'DisplayMonitorInfoBamoClientConnection' in r['name']) and not any(x in r['name'] for x in ['?$','??_','??$']):print(hex(r['rva']),r['name'])
