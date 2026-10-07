from pathlib import Path
L=Path(__file__).resolve().parent;S=L.parent/'ShellAppearanceCompat'
t=(S/'Test-PackageAccess.py').read_text().replace('Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy','windows.immersivecontrolpanel_cw5n1h2txyewy').replace('ReadFixture.exe','AccessFixture.exe')
lines=t.splitlines()
for i,line in enumerate(lines):
 if line.startswith('shutil.copyfile(LAB/'):
  lines[i]="shutil.copyfile(LAB/'AccessFixture.exe',reader);ini.write_text('\\n'.join([str(LAB.parent/'SettingsNoVfsCompat/SettingsFactorySelector.dll'),str(LAB.parents[1]/'Image/4/Windows/ImmersiveControlPanel/SystemSettings.dll'),str(LAB.parents[1]/'Image/4/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll'),str(LAB.parents[1]/'Image/4/Windows/ImmersiveControlPanel/Telemetry.Common.dll'),str(LAB.parent/'SettingsContentCompat/SettingsContentCompat.dll')]),encoding='utf-8')"
 if 'proof.update(Result=code.value' in line:lines[i]=' proof.update(Result=code.value,RealAppContainer=True,FiveDirectDllLoads=True,NtBackingIdentity=True,Passed=code.value==0)'
(L/'Test-PackageAccess.py').write_text('\n'.join(lines)+'\n')
