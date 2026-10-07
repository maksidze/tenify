#include <windows.h>
#include <stdio.h>
#include <wchar.h>
int BrokerExistingWmain(int argc,wchar_t**argv){return argc==7&&!wcscmp(argv[1],L"--config")?100:101;}
