from pathlib import Path
p=Path('outputs/Windows10-Components/Lab/SettingsBrokerCompat/SettingsBrokerProbe.c');s=p.read_text()
s=s.replace('diagAddress[4]','diagAddress[5]').replace('diagOriginal[4]','diagOriginal[5]').replace('diagActive[4]','diagActive[5]').replace('for(int i=0;i<4;i++)if(diagActive','for(int i=0;i<5;i++)if(diagActive')
needle='if(wcsstr(clean,L"Image\\\\4\\\\Windows\\\\ImmersiveControlPanel\\\\SystemSettings.dll"))installDiag(pi.hProcess,e.u.LoadDll.lpBaseOfDll);'
new=needle+r'''if(wcsstr(clean,L"Image\\4\\Windows\\ImmersiveControlPanel\\SystemSettingsViewModel.Desktop.dll")){BYTE*target=(BYTE*)e.u.LoadDll.lpBaseOfDll+0x4b9b0;BYTE expected[10]={0x49,0x8b,0x01,0x49,0x8b,0xc9,0x48,0x8b,0x40,0x40},got[10]={0};SIZE_T read=0;DWORD old=0,unused=0;BYTE trap=0xcc;if(ReadProcessMemory(pi.hProcess,target,got,10,&read)&&!memcmp(expected,got,10)&&VirtualProtectEx(pi.hProcess,target,1,PAGE_EXECUTE_READWRITE,&old)){WriteProcessMemory(pi.hProcess,target,&trap,1,&read);VirtualProtectEx(pi.hProcess,target,1,old,&unused);FlushInstructionCache(pi.hProcess,target,1);diagAddress[4]=target;diagOriginal[4]=expected[0];diagActive[4]=TRUE;logline("DIAG_SETTING_ID_INSTALLED %p",target);}else logline("DIAG_SETTING_ID_GUARD mismatch=%02x",got[0]);}'''
assert needle in s;s=s.replace(needle,new)
needle='if(i==3){ULONGLONG reader=0;'
new=r'''if(i==4){BYTE header[24]={0};WCHAR setting[257]={0};if(readChild(pi.hProcess,(void*)c.Rdx,header,sizeof(header))){DWORD length=*(DWORD*)(header+4);ULONGLONG buffer=*(ULONGLONG*)(header+16);logline("DIAG_SETTING_HSTRING ptr=%llx flags=%lx length=%lu buffer=%llx",c.Rdx,*(DWORD*)header,length,buffer);if(length<=256&&readChild(pi.hProcess,(void*)buffer,setting,length*2))logline("DIAG_SETTING_ID %ls",setting);}}
   '''+needle
s=s.replace(needle,new);p.write_text(s)
