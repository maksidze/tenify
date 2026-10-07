from pathlib import Path
for name in ['WindowsInternal.ComposableShell.Display.dll','windowsudkservices.shellcommon.dll','CoreShell.dll','DesktopShellExt.dll','Windows.Internal.ShellCommon.dll','Windows.UI.Shell.dll']:
 p=Path('C:/Windows')/('explorer.exe' if name=='explorer.exe' else 'System32/'+name);b=p.read_bytes()
 for needle in ['WindowsUdk.UI.Shell.DisplayMonitorInfoCollectionServer', 'WindowsUdk.UI.Shell.DisplayMonitorInfoCollection','DisplayMonitorInfoConversation_','DisplayMonitorInfoCollectionServer']:
  off=b.find(needle.encode('utf-16-le'))
  print(name,needle,hex(off) if off>=0 else 'absent')



