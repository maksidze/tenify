import sys,json,struct
sys.path.insert(0,'work/pylib');import pefile
p=pefile.PE('work/settings-datamodel-image/4/Windows/System32/SystemSettings.DataModel.dll');s=json.load(open('work/compat-research/old-settings-datamodel/all-public-symbols.json')); d={x['rva']:x['name'] for x in s}
vs=[x for x in s if x['name'].startswith('??_7SettingsEnvironmentDatabaseServer') and '6BISettingsEnvironmentDatabase' in x['name']];print(vs)
for v in vs:
 for i,a in enumerate(struct.unpack('<12Q',p.get_data(v['rva'],96))):print(i,hex(a-p.OPTIONAL_HEADER.ImageBase),d.get(a-p.OPTIONAL_HEADER.ImageBase,'?'))
