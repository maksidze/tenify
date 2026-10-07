from pathlib import Path
p=Path('outputs/Windows10-Components/Lab/SettingsBrokerCompat/SettingsBrokerProbe.c')
s=p.read_text()
old='if(readChild(pi.hProcess,(void*)c.Rsp,stack,stackWords*8))for(unsigned i=0;i<stackWords;i++)logline("STACK +%x=%llx",i*8,stack[i]);'
new='for(unsigned i=0;i<stackWords;i++){if(!readChild(pi.hProcess,(void*)(c.Rsp+i*8),stack+i,8))break;logline("STACK +%x=%llx",i*8,stack[i]);}'
assert old in s
p.write_text(s.replace(old,new))
