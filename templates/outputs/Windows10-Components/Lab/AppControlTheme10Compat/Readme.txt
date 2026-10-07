Private Win32 app theme, without VFS — 2026-10-06
The x64 app is selected by captured PID, creation FILETIME, exact path and SHA256.
Only common-controls Button/Edit/ComboBox requests on their owning UI thread at
96 DPI use the genuine private Windows10 theme. Process current theme remains
native, folder dialogs stay functional. High contrast/other classes stay native.
This does not style custom-drawn, WinUI, Qt/Electron or x86 interfaces.

Apply.py is one controlled memory-only installer, not a global hook. It checks
actual import pointers and queues WM_THEMECHANGED only for target app controls.
GetWindowTheme handles are NOT dereferenced from its remote worker; genuine
request counters are used. Installed module/provider live until the app closes.
Live hot Restore is unsupported. Close/reopen the app normally to restore.
Generic config initializer and repaint of an already-existing own Button passed
real hidden-desktop tests, with exact native paint restoration in quiescent fixture.
No app commands, update settings or system files are changed.
