typedef struct {const WCHAR* relative;const char* hash;const char* entry;} Adapter;
static const Adapter adapters[]={
{L"..\\SettingsCaptionCompat\\SettingsCaptionCompat.dll","1db421eab2d8272b4d708ac1d305a54bf9c79716ff5fe0035579b3b4e6ea8ab8","SettingsInitialize"},
{L"..\\SettingsControlTextCompat\\SettingsControlTextCompat.dll","d294664b83358a11e5ff2230a10f5b8447bfd910b1509b591623a671afaecc66","SettingsControlTextInitialize"},
{L"..\\SettingsPowerCompat\\SettingsPowerCompat.dll","699f0fdea0ddcb12e9b3c5c9abc0fec0494f327ad72bd8d0d364be0f26ceb56c","SettingsPowerInitialize"},
};