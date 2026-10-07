from pathlib import Path
s=Path('work/Test-SettingsDynamicTextDiag.c').read_text().replace('SettingsPageGroupNetwork",24','SettingsPageGroupApps",21').replace('DatamodelTextDynamic(Network)','DatamodelTextDynamic(Apps)');Path('work/Test-SettingsDynamicTextCompat.c').write_text(s)
s=Path('work/probe_settings_datamodel_package.ps1').read_text().replace('Test-SettingsDataModelQuery','Test-SettingsDynamicTextCompat').replace('settings-host-datamodel-package-query.log','settings-dynamictext-compat-own-query.log')
h=Path('outputs/Windows10-Components/Lab/SettingsDynamicTextCompat/SettingsDynamicTextCompat.dll').resolve()
s=s.replace('"C:\\Windows\\System32\\SystemSettings.DataModel.dll" "{0}"','"C:\\Windows\\System32\\SystemSettings.DataModel.dll" "{0}" "'+str(h)+'"')
Path('work/probe_settings_dynamictext_compat_package.ps1').write_text(s)
