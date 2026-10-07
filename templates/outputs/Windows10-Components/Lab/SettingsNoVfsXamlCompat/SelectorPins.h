#define NATIVE_EXE_PATH L"C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe"
#define NATIVE_EXE_SHA "50db6a50fc541e24f31fdcb240c97c9d3c267afc4de907bf1dcf9238ef2a914b"
#define OWN_EXE_PATH L"@WORKSPACE_ESC@\\outputs\\Windows10-Components\\Lab\\SettingsNoVfsXamlCompat\\Fixture.exe"
#define OWN_EXE_SHA "efa3030245e10c52d06cdf36796652e7ab416cfa3f1e17deedcad8f4c0728446"
struct MODPIN{PCWSTR path;const char*sha;DWORD ro,pc;};
static const MODPIN modulePins[]={
{L"@WORKSPACE_ESC@\\outputs\\Windows10-Components\\Image\\4\\Windows\\ImmersiveControlPanel\\SystemSettings.dll","ac0ed6871e27b600e338efe8cc56d28410a83b1e5ec4555670eb1ef3ff0f8d45",0x46d650,0x46df98},
{L"@WORKSPACE_ESC@\\outputs\\Windows10-Components\\Image\\4\\Windows\\ImmersiveControlPanel\\SystemSettingsViewModel.Desktop.dll","a56da88f90b9464dbfe29d792cbacf837363be8b3af3225b759ef4b9c61249c1",0x83350,0x83910},
{L"@WORKSPACE_ESC@\\outputs\\Windows10-Components\\Image\\4\\Windows\\ImmersiveControlPanel\\Telemetry.Common.dll","e81f727bcb26dc215f71b8b339ba26b16bbe690dd55f014e623468baf8a3ea5a",0x0,0x0},
};